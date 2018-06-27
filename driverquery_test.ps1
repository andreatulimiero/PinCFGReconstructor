$TESTS_NUM = 5

function clear_env() {
    Invoke-Expression "rm trace*"
}

function runTests ($tag, $cmd) {
    $highest = -1;
    $lowest = 999999;
    $totalMillisecondsSum = 0
    for ($i = 0; $i -lt $TESTS_NUM; $i++) {
        clear_env
        Write-Host "[($i) $tag]"
        $time_span = Measure-Command { Invoke-Expression "$cmd" }
        $totalMilliseconds = $time_span.TotalMilliseconds
        $totalMillisecondsSum += $totalMilliseconds
        if ($totalMilliseconds -gt $highest) { $highest = $totalMilliseconds }
        if ($totalMilliseconds -lt $lowest)  { $lowest = $totalMilliseconds }
    }
    $totalMillisecondsSum -= ($highest + $lowest)
    $avg_time = $totalMillisecondsSum / ($TESTS_NUM - 2)
    Write-Host "Average time: $avg_time"
}

Write-Host "--- Beginning Tests for driverquery /v ---"
$PROG = "driverquery /v"
$BASE = "C:\Pin35\pin.exe -t C:\Pin35\icount32.dll -trace_limit 2048"

runTests "Original" "$PROG"
runTests "Flushed" "$BASE -- $PROG"
runTests "Buffered version (50Mb)" "$BASE -buffered -thread_buffer_size 50 -- $PROG"
runTests "Buffered version (300Mb)" "$BASE -buffered -thread_buffer_size 300 -favor_main_thread -- $PROG"
runTests "Thread flushed version (50Mb)" "$BASE -thread_flushed -thread_buffer_size 50 -- $PROG"
runTests "Thread flushed version (200Mb)" "$BASE -buffered -thread_buffer_size 200 -favor_main_thread -- $PROG"