package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kong"
	"github.com/aquasecurity/table"
	client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/auto"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/hashicorp/go-multierror"
	"github.com/rs/zerolog"
	"github.com/schollz/progressbar/v3"
)

const (
	maxCommitteesPerSlot = 64
	maxInclusionDelay    = 32
	slotsPerEpoch        = 32
)

var cli struct {
	Concurrency int      `short:"c" help:"Per-node concurrency limit" default:"16"`
	Node        []string `help:"Comma-separated Beacon node addresses, such as http://localhost:3500,http://localhost:5052"`
	Epochs      string   `required:""`
}

func main() {
	kong.Parse(&cli)

	ctx := context.Background()
	clients := make([]client.Service, len(cli.Node))
	var g multierror.Group
	for i, node := range cli.Node {
		i, node := i, node
		g.Go(func() error {
			cl, err := auto.New(
				ctx,
				auto.WithAddress(node),
				auto.WithLogLevel(zerolog.ErrorLevel),
			)
			if err != nil {
				return err
			}
			clients[i] = cl
			return nil
		})
	}
	err := g.Wait().ErrorOrNil()
	if err != nil {
		log.Fatal(err)
	}

	// Parse epochs.
	var fromEpoch, toEpoch phase0.Epoch
	parts := strings.Split(cli.Epochs, "-")
	switch len(parts) {
	case 2:
		f, err := strconv.Atoi(parts[0])
		if err != nil {
			log.Fatal(err)
		}
		fromEpoch = phase0.Epoch(f)
		t, err := strconv.Atoi(parts[1])
		if err != nil {
			log.Fatal(err)
		}
		toEpoch = phase0.Epoch(t)
	case 1:
		n, err := strconv.Atoi(parts[0])
		if err != nil {
			log.Fatal(err)
		}
		fromEpoch, toEpoch = phase0.Epoch(n), phase0.Epoch(n)
	}

	if fromEpoch > toEpoch {
		log.Fatal("fromEpoch is bigger than toEpoch")
	}
	if toEpoch-fromEpoch > 1575 {
		log.Fatal("That's too many epochs, bruh?")
	}

	// Fetch the blocks.
	start := time.Now()
	fromSlot := phase0.Slot(fromEpoch * 32)
	toSlot := phase0.Slot(toEpoch*32) + 31
	type blockWithRoot struct {
		Root phase0.Root
		*bellatrix.SignedBeaconBlock
	}
	var messyBlocks []blockWithRoot
	g = multierror.Group{}
	var concurrencyLimit sync.Map
	for i := range clients {
		concurrencyLimit.Store(i, make(chan struct{}, cli.Concurrency))
	}
	bar := progressbar.Default(int64(toSlot - fromSlot + maxInclusionDelay + 1))
	for slot := fromSlot; slot <= toSlot+maxInclusionDelay; slot++ {
		s := slot
		g.Go(func() error {
			ch, _ := concurrencyLimit.Load(rand.Intn(len(clients)))
			ch.(chan struct{}) <- struct{}{}
			defer func() {
				bar.Add(1)
				<-ch.(chan struct{})
			}()
			bl, err := clients[rand.Intn(len(clients))].(client.SignedBeaconBlockProvider).SignedBeaconBlock(ctx, fmt.Sprint(s))
			if err != nil {
				if strings.Contains(err.Error(), "Could not find requested block") {
					return nil
				}
				return err
			}
			if bl == nil {
				return nil
			}
			root, err := bl.Bellatrix.Message.HashTreeRoot()
			if err != nil {
				return err
			}
			bl.Bellatrix.Message.Body.ExecutionPayload = nil // Free some memory. We don't need the payload.
			messyBlocks = append(messyBlocks, blockWithRoot{root, bl.Bellatrix})
			return nil
		})
	}
	err = g.Wait().ErrorOrNil()
	if err != nil {
		log.Fatal(err)
	}
	sort.Slice(
		messyBlocks,
		func(i, j int) bool { return messyBlocks[i].Message.Slot < messyBlocks[j].Message.Slot },
	)
	log.Printf("Got %d blocks", len(messyBlocks))
	timingFetchBlocks := time.Since(start)

	// Sort the blocks, discarding orphans.
	roots := map[phase0.Slot]phase0.Root{}
	blocks := []blockWithRoot{messyBlocks[len(messyBlocks)-1]}
	start = time.Now()
	for i := len(messyBlocks) - 1; i >= 0; i-- {
		for j, bl := range messyBlocks {
			if i == j {
				continue
			}
			root, ok := roots[bl.Message.Slot]
			if !ok {
				roots[bl.Message.Slot] = bl.Root
			}
			if messyBlocks[i].Message.ParentRoot == root {
				blocks = append(blocks, bl)
			}
		}
	}
	sort.Slice(
		blocks,
		func(i, j int) bool { return blocks[i].Message.Slot < blocks[j].Message.Slot },
	)
	fmt.Printf("Processed blocks within %s\n\n", time.Since(start))
	timingSortBlocks := time.Since(start)

	// for _, bl := range blocks {
	// 	log.Println(bl.Message.Slot)
	// }
	// return

	// Organize participations.
	start = time.Now()
	type AttesterParticipation struct {
		Included      bool
		InclusionSlot phase0.Slot
	}
	type CommitteeParticipation []AttesterParticipation

	slotCommitteeParticipations := make(
		[][maxCommitteesPerSlot]CommitteeParticipation,
		toSlot-fromSlot+1,
	)
	blocksInRange := 0
	for _, bl := range blocks {
		if bl.Message.Slot >= fromSlot && bl.Message.Slot <= toSlot {
			blocksInRange++
		}
		for _, att := range bl.Message.Body.Attestations {
			if att.Data.Slot < phase0.Slot(fromSlot) || att.Data.Slot > phase0.Slot(toSlot) {
				continue
			}
			slotIndex := att.Data.Slot - phase0.Slot(fromSlot)
			participations := slotCommitteeParticipations[slotIndex][att.Data.Index]
			if participations == nil {
				participations = make(CommitteeParticipation, att.AggregationBits.Len())
			}
			for _, i := range att.AggregationBits.BitIndices() {
				if !participations[i].Included {
					participations[i].Included = true
					participations[i].InclusionSlot = bl.Message.Slot
				}
			}
			slotCommitteeParticipations[slotIndex][att.Data.Index] = participations
		}
	}
	timingOrganizeParticipations := time.Since(start)

	// for idx, participations := range committeeParticipations {
	// 	fmt.Printf("%d:\n", idx)
	// 	for _, p := range participations {
	// 		s := "❌"
	// 		if p.Included {
	// 			s = "✅"
	// 		}
	// 		fmt.Printf("%s%d", s, p.InclusionSlot-phase0.Slot(fromSlot))
	// 	}
	// 	fmt.Println()
	// }
	// fmt.Println()

	// Calculate participation.
	start = time.Now()
	var (
		assigned, executed                             = 0, 0
		inclusionDelay                                 phase0.Slot
		slotAssigned, slotExecuted, slotInclusionDelay [slotsPerEpoch]int
	)
	for slot, committees := range slotCommitteeParticipations {
		slot += int(fromSlot)
		slotIndex := slot % 32
		var earliestInclusionSlot phase0.Slot
		for _, bl := range blocks {
			if bl.Message.Slot > phase0.Slot(slot) {
				earliestInclusionSlot = bl.Message.Slot
				break
			}
		}
		if earliestInclusionSlot == 0 {
			// log.Fatal("No inclusions...")
			continue
		}

		for _, participations := range committees {
			assigned += len(participations)
			slotAssigned[slotIndex] += len(participations)
			for _, p := range participations {
				if p.Included {
					executed++
					slotExecuted[slotIndex]++

					delay := 1 + p.InclusionSlot - earliestInclusionSlot
					inclusionDelay += delay
					slotInclusionDelay[slotIndex] += int(delay)
				}
			}
		}
	}
	timingCalculateParticipation := time.Since(start)

	fmt.Printf("Slots\n")
	tbl := table.New(os.Stdout)
	tbl.AddHeaders("Slot", "Assigned", "Executed", "Rate", "Effectiveness")
	for i := 0; i < 32; i++ {
		assigned := slotAssigned[i]
		executed := slotExecuted[i]
		inclusionDelay := slotInclusionDelay[i]
		tbl.AddRow(
			fmt.Sprint(i),
			fmt.Sprint(assigned),
			fmt.Sprint(executed),
			fmt.Sprintf("%.2f%%", float64(executed)/float64(assigned)*100),
			fmt.Sprintf("%.2f%%", 1/(float64(inclusionDelay)/float64(executed))*100),
		)
	}
	tbl.Render()
	fmt.Println()

	fmt.Printf("Timings\n")
	tbl = table.New(os.Stdout)
	tbl.AddHeaders("FetchBlocks", "SortBlocks", "OrganizeParticipations", "CalculateParticipation")
	tbl.AddRow(
		fmt.Sprint(timingFetchBlocks),
		fmt.Sprint(timingSortBlocks),
		fmt.Sprint(timingOrganizeParticipations),
		fmt.Sprint(timingCalculateParticipation),
	)
	tbl.Render()
	fmt.Println()

	fmt.Printf("Scope\n")
	tbl = table.New(os.Stdout)
	tbl.AddHeaders(fmt.Sprintf("%d Epochs", toEpoch-fromEpoch+1), "Proposal Rate")
	tbl.AddRow(
		fmt.Sprintf("%d—%d", fromEpoch, toEpoch),
		fmt.Sprintf("%.2f%%", float64(blocksInRange)/float64(toSlot-fromSlot+1)*100),
	)
	tbl.Render()
	fmt.Println()

	fmt.Printf("Attestations\n")
	tbl = table.New(os.Stdout)
	tbl.AddHeaders("Assigned", "Executed", "Rate", "Effectiveness")
	tbl.AddRow(
		fmt.Sprint(assigned),
		fmt.Sprint(executed),
		fmt.Sprintf("%.2f%%", float64(executed)/float64(assigned)*100),
		fmt.Sprintf("%.2f%%", 1/(float64(inclusionDelay)/float64(executed))*100),
	)
	tbl.Render()
}
