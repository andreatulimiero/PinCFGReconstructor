$TESTS_NUM = 5
$TRACE_LIMIT = 10240

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

$PROG = "driverquery /v"
$BASE = "C:\Pin35\pin.exe -t C:\Pin35\icount32.dll -trace_limit $TRACE_LIMIT"
Write-Host "--- Beginning Tests for --- $PROG"

$SM_THREAD_BUF = 30
$XL_THREAD_BUF = 200

runTests "Original" "$PROG"
# runTests "Flushed" "$BASE -- $PROG"
runTests "Buffered version ($SM_THREAD_BUF Mb)" "$BASE -buffered -thread_buffer_size $SM_THREAD_BUF -- $PROG"
runTests "Buffered version ($XL_THREAD_BUF Mb)" "$BASE -buffered -thread_buffer_size $XL_THREAD_BUF -favor_main_thread -- $PROG"
runTests "Thread flushed version ($SM_THREAD_BUF Mb)" "$BASE -thread_flushed -thread_buffer_size $SM_THREAD_BUF -- $PROG"
runTests "Thread flushed version ($XL_THREAD_BUF Mb)" "$BASE -buffered -thread_buffer_size $XL_THREAD_BUF -favor_main_thread -- $PROG"