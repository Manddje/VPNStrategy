$users = Get-ChildItem (Join-Path -Path $env:SystemDrive -ChildPath 'Users') -Exclude 'Public', '_adm*', 'ADMINI~*'
if ($null -ne $users) {
    foreach ($user in $users) {
        $progPath = Join-Path -Path $user.FullName -ChildPath "AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk" 
        
        # Check if VPNStrategy is set to 14
        $VpnStrategy = get-content $progPath
        
        if ($VpnStrategy -like "*VpnStrategy=14*"){
        Write-Output "Correct value"
        echo $progPath
        exit 0
        }
   Else 
        {
        Write-Output "Wrong value"
        echo $progPath
        exit 1
        }
    }
}