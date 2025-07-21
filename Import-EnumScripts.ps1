

function Get-ProcessForTCPPort {
    param (
        [int]$Port
    )

    Get-Process -Id (Get-NetTCPConnection -LocalPort $Port).OwningProcess
}

function Get-ProcessForUDPPort {
    param (
        [int]$Port
    )

    Get-Process -Id (Get-NetUDPEndpoint -LocalPort $Port).OwningProcess
}
