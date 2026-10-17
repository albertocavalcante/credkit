$ErrorActionPreference = 'Stop'

# Test fixtures must inherit a known private ACL. The host TEMP may grant
# additional users access; never repair an existing host directory for tests.
$privateTemp = Join-Path ([IO.Path]::GetTempPath()) ('credkit-tests-' + [guid]::NewGuid())
$oldTemp, $oldTmp = $env:TEMP, $env:TMP
$createdTemp = $false
Push-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)
try {
    New-Item -ItemType Directory -Path $privateTemp | Out-Null
    $createdTemp = $true
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($user)
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($sid in @($user, [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $privateTemp -AclObject $acl
    $env:TEMP = $privateTemp
    $env:TMP = $privateTemp

    go build ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go build failed' }
    go test -v -count=1 ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go vet failed' }
} finally {
    $env:TEMP = $oldTemp
    $env:TMP = $oldTmp
    Pop-Location
    if ($createdTemp) {
        Remove-Item -LiteralPath $privateTemp -Recurse -Force
    }
}
