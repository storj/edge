// Copyright (C) 2021 Storj Labs, Inc.
// See LICENSE for copying information.

package sharing

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"storj.io/common/errs2"
	"storj.io/common/testcontext"
	"storj.io/common/testrand"
)

func randSleep() {
	time.Sleep(time.Duration(testrand.Intn(50)) * time.Microsecond)
}

func TestMutexGroup(t *testing.T) {
	defer testcontext.NewWithTimeout(t, time.Minute).Cleanup()

	var accesses errs2.Group

	var muGroup MutexGroup
	var counters [3]*int32
	totalCounter := new(int32)
	for lockNo := 0; lockNo < len(counters); lockNo++ {
		counters[lockNo] = new(int32)
		for workerNo := 0; workerNo < 10; workerNo++ {
			lockNo := lockNo
			accesses.Go(func() error {
				lockName := fmt.Sprint(lockNo)

				highwater := int32(0)

				for i := 0; i < 100; i++ {
					randSleep()
					err := func() error {
						unlock := muGroup.Lock(lockName)
						defer unlock()

						incr := atomic.AddInt32(counters[lockNo], 1)
						if incr != 1 {
							return fmt.Errorf("expected incr %v got %v;", 1, incr)
						}

						total := atomic.AddInt32(totalCounter, 1)
						if total > int32(len(counters)) {
							return fmt.Errorf("total %v > counters %v;", total, len(counters))
						}
						if total > highwater {
							highwater = total
						}
						randSleep()

						decr := atomic.AddInt32(counters[lockNo], -1)
						if decr != 0 {
							return fmt.Errorf("expected decr %v got %v;", 0, decr)
						}

						totalAfter := atomic.AddInt32(totalCounter, -1)
						if totalAfter < 0 {
							return fmt.Errorf("total was negative, got %v;", totalAfter)
						}

						return nil
					}()
					if err != nil {
						return err
					}
				}

				if highwater != int32(len(counters)) {
					return fmt.Errorf("highwater %v != len(counters) %v;", highwater, len(counters))
				}
				return nil
			})
		}
	}
	require.Empty(t, accesses.Wait())

	require.Equal(t, int32(0), *totalCounter)
	for lockNo := 0; lockNo < len(counters); lockNo++ {
		require.Equal(t, int32(0), *counters[lockNo])
	}
}
