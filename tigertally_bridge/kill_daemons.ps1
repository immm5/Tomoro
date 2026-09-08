Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'python.exe' -and $_.CommandLine -like '*signer_daemon*' } | ForEach-Object {
  Write-Output ('KILL PID ' + $_.ProcessId)
  Stop-Process -Id $_.ProcessId -Force
}