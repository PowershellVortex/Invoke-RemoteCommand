$logo = @'

 LOGO

'@
Get-WmiObject win32_operatingsystem | Select-Object @{ LABEL='LastBootUpTime' ; EXPRESSION={ $_.ConverttoDateTime( $_.lastbootuptime )}},Version
$logo
 
