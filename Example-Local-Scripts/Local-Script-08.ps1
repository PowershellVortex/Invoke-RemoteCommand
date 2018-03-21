$langList = Get-WinUserLanguageList
$langList.add("pl-PL")
$langList.add("en-US")
Set-WinUserLanguageList $langList