$TESTS_NUM = 2
$TRACE_LIMIT = 4090

function clear_env() {
    Invoke-Expression "rm trace*"
}

function clear_reports() {
    Invoke-Expression "rm *.report"
}

function runTests ($tag, $cmd, $arguments) {
    # $highest = -1;
    # $lowest = 999999;
    $totalMillisecondsSum = 0
    for ($i = 0; $i -lt $TESTS_NUM; $i++) {
        clear_env
        Write-Host "[($i) $tag]"
        $report_tag = "$(Get-Date -Format FileDateTime)" + ".report"
        $time_span = Measure-Command { Invoke-Expression "$cmd -tag $report_tag $arguments" | Out-Default  }
        $totalMilliseconds = $time_span.TotalMilliseconds
        $totalMillisecondsSum += $totalMilliseconds
        # if ($totalMilliseconds -gt $highest) { $highest = $totalMilliseconds }
        # if ($totalMilliseconds -lt $lowest)  { $lowest = $totalMilliseconds }
    }
    # $totalMillisecondsSum -= ($highest + $lowest)
    # $avg_time = $totalMillisecondsSum / ($TESTS_NUM - 2)
    $avg_time = ($totalMillisecondsSum / $TESTS_NUM)
    Write-Host "{$tag Average time: $avg_time}"
}

$PROG = "C:\Users\tulim\Downloads\fciv.exe -md5 -sha1 C:\Users\tulim\Downloads\sd_backup.img"
$BASE = "C:\Pin35\pin.exe -t C:\Pin35\icount32.dll -trace_limit $TRACE_LIMIT"
Write-Host "--- Beginning Tests for --- $PROG"

$XS_THREAD_BUF = 10
$SM_THREAD_BUF = 30
$MD_THREAD_BUF = 50
$LG_THREAD_BUF = 100
$XL_THREAD_BUF = 200

# runTests "Original" "$PROG"
# runTests "Flushed" "$BASE -- $PROG"

# runTests "Buffered ($SM_THREAD_BUF Mb)" $BASE "-buffered -thread_buffer_size $SM_THREAD_BUF -- $PROG"

runTests "Thread flushed ($SM_THREAD_BUF Mb)" $BASE "-thread_flushed -thread_buffer_size $SM_THREAD_BUF -- $PROG"