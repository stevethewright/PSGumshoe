<#
.SYNOPSIS
    Builds and executes a dynamic XML filter to query Sysmon event logs based on user-defined parameters.
.DESCRIPTION
    Constructs a flexible XML filter for querying Sysmon logs using Get-WinEvent.
    It supports filtering by multiple Event IDs, custom field values, time ranges and log paths. The function also
    supports remote querying with optional credentials and can suppress specific results using a Suppress filter block.
    It outputs results in a structured format by piping them through a helper function ConvertFrom-SysmonEventLogRecord,
    which is assumed to parse raw event log entries into a more readable object.
.EXAMPLE
    Search-SysmonEvent -ParamHash @{ Path = 'C:\Logs\Sysmon.evtx' } -EventId 1
    Searches for Sysmon Event ID 1 in the specified log file.
.EXAMPLE
    Search-SysmonEvent -ParamHash @{ Path = 'C:\Logs\Sysmon.evtx'; Image = 'cmd.exe' } -EventId 1
    Searches for Event ID 1 where the 'Image' field equals 'cmd.exe'.
.EXAMPLE
    Search-SysmonEvent -ParamHash @{ ComputerName = 'RemotePC'; Credential = (Get-Credential); Path = 'Microsoft-Windows-Sysmon/Operational' } -EventId 3
    Queries Event ID 3 from a remote machine using provided credentials.
#>
function Search-SysmonEvent {
    [CmdletBinding()]
    param (
        # Parameters of cmdlet using this helper function.
        $ParamHash,

        # Sysmon Event Id to filter on
        [int[]]
        $EventId,

        # Record type to output.
        [string]
        $RecordType
    )

    begin {

        # Get paramters for use in creating the filter.
        #$Params = $MyInvocation.BoundParameters.Keys
        $Params = $ParamHash.keys
        $CommonParams = ([System.Management.Automation.Cmdlet]::CommonParameters) + @('Credential', 'ComputerName', 'MaxEvents', 'StartTime', 'EndTime', 'Path', 'ChangeLogic','ActivityType','Suppress')

        $FinalParams = @()
        foreach ($p in $Params) {
            if ($p -notin $CommonParams) {
                $FinalParams += $p
            }
        }
        # Build filters based on options available.
        if ($EventId.Length -gt 1) {
            $IdFilterCount = 0
            foreach($id in $EventId) {
                if ($IdFilterCount -eq 0) {
                   $idFilter =  "(System/EventID=$($id))"
                } else {
                    $idFilter += " or (System/EventID=$($id))"
                }
                $IdFilterCount++
            }
            $SelectFilter = "`n*[System/Provider[@Name='microsoft-windows-sysmon'] and ($($idFilter))] "
        } else {
            $SelectFilter = "`n(*[System/Provider[@Name='microsoft-windows-sysmon'] and (System/EventID=$($EventId))] )"
        }


        $filter = " "
        # Manage change in Logic
        $logicOperator = 'and'
        if ($ParamHash['ChangeLogic']) {
            Write-Verbose -Message 'Logic per field has been inverted.'
           $logicOperator = 'or'
        }
        $filterBlockCount = 0
        foreach ($Param in $FinalParams) {
            if ($param -notin $CommonParams) {
               $FieldValue = $ParamHash["$($param)"]
               $FilterCount = 0
               foreach($val in $FieldValue) {
                    if ($FilterCount -gt 0) {
                       $filter = $filter + "`n or *[EventData[Data[@Name='$($Param)']='$($val)']]"
                    } else {
                        if ($Params -contains 'Suppress') {
                            $filter = $filter + "`n (*[EventData[Data[@Name='$($Param)']='$($val)']]"
                        } else {
                            if ($filterBlockCount -gt 0) {
                                $filter = $filter + "`n $( $logicOperator ) (*[EventData[Data[@Name='$($Param)']='$($val)']]"
                            } else {
                                $filter = $filter + "`n and (*[EventData[Data[@Name='$($Param)']='$($val)']]"
                                $filterBlockCount += 1
                            }
                        }
                    }
                   $FilterCount += 1
               }
               $filter += ") "
            }
        }

        if ($StartTime -ne $null) {
            $StartTime = $StartTime.ToUniversalTime()
            $StartTimeFormatted = $StartTime.ToString("s",[cultureinfo]::InvariantCulture)+"."+ ($StartTime.Millisecond.ToString("d3",[cultureinfo]::InvariantCulture))+"z"
            $filter = $filter + "`n and *[System/TimeCreated[@SystemTime&gt;='$( $StartTimeFormatted )']]"
        }

        if ($EndTime -ne $null) {
            $EndTime = $EndTime.ToUniversalTime()
            $EndTimeFormatted = $EndTime.ToString("s",[cultureinfo]::InvariantCulture)+"."+ ($EndTime.Millisecond.ToString("d3",[cultureinfo]::InvariantCulture))+"z"
            $filter = $filter + "`n and *[System/TimeCreated[@SystemTime&lt;='$( $EndTimeFormatted )']]"
        }

        # Concatenate all the filters in to one single XML Filter.
        if ($Params -contains 'Path') {
            # Initiate variable that will be used for the Query Id for each in the QueryList.
            $QueryId = 0
            $Querys = ''

            # Resolve all paths provided and process each.
            (Resolve-Path -Path $ParamHash['Path']).Path | ForEach-Object {
                if ($FilterCount -eq 0) {
                    $Querys += "`n<Query Id='$($QueryId)' Path='file://$($_)'>`n<Select>$($SelectFilter + $filter)`n</Select>`n</Query>"
                } else {
                    if ($Params -contains 'Suppress') {
                        $Querys = "<QueryList>`n<Query Id='0' Path='file://$($_)'>`n"
                        $Querys += "<Select Path='file://$($_)'>$($SelectFilter)`n</Select>`n"
                        $Querys += "<Suppress Path='file://$($_)'>$($filter)`n</Suppress>`n"
                        $Querys += "</Query>`n</QueryList>"

                    } else {
                        $Querys += "`n<Query Id='$($QueryId)' Path='file://$($_)'>`n<Select>$($SelectFilter + $filter)`n</Select>`n</Query>"
                    }
                }
                $QueryId++
            }
            $BaseFilter = "<QueryList>`n$($Querys)`n</QueryList>"
        } else {
            if ($FilterCount -eq 0) {
               $BaseFilter = "<QueryList>`n<Query Id='0' Path='$($LogName)'>`n<Select Path='$($LogName)'>$($SelectFilter + $filter)`n</Select>`n</Query>`n</QueryList>"
            } else {
                if ($Params -contains 'Suppress') {
                    $BaseFilter = "<QueryList>`n<Query Id='0' Path='$($LogName)'>`n"
                    $BaseFilter += "<Select Path='$($LogName)'>$($SelectFilter)`n</Select>`n"
                    $BaseFilter += "<Suppress Path='$($LogName)'>$($filter)`n</Suppress>`n"
                    $BaseFilter += "</Query>`n</QueryList>"
                } else {
                    $BaseFilter = "<QueryList>`n<Query Id='0' Path='$($LogName)'>`n<Select Path='$($LogName)'>$($SelectFilter + $filter)`n</Select>`n</Query>`n</QueryList>"
                }
            }

        }

        Write-Verbose -Message $BaseFilter
   }

   process {

       # Perform query and turn results in to a more easy to parse object.
       if ($Params.Contains("ComputerName")) {
            $ParamHash["ComputerName"] | ForEach-Object {
                if ($params -notcontains 'Credential') {
                    if ($MaxEvents -gt 0) {
                        Get-WinEvent -FilterXml $BaseFilter -MaxEvents $MaxEvents -ComputerName $_ -ErrorAction SilentlyContinue | ConvertFrom-SysmonEventLogRecord
                    } else {
                        Get-WinEvent -FilterXml $BaseFilter -ComputerName $_ -ErrorAction SilentlyContinue | ConvertFrom-SysmonEventLogRecord
                    }
                } else {
                    if ($MaxEvents -gt 0) {
                        Get-WinEvent -FilterXml $BaseFilter -MaxEvents $MaxEvents -ComputerName $_ -Credential $Credential -ErrorAction SilentlyContinue  | ConvertFrom-SysmonEventLogRecord
                    } else {
                        Get-WinEvent -FilterXml $BaseFilter -ComputerName $_ -Credential $Credential -ErrorAction SilentlyContinue | ConvertFrom-SysmonEventLogRecord
                    }
                }
            }
        }
        else {
            if ($MaxEvents -gt 0) {
                Get-WinEvent -FilterXml $BaseFilter -ErrorAction SilentlyContinue  -MaxEvents $MaxEvents | ConvertFrom-SysmonEventLogRecord
            } else {
                Get-WinEvent -FilterXml $BaseFilter -ErrorAction SilentlyContinue | ConvertFrom-SysmonEventLogRecord
            }
        }
    }
   
    end {
    }
}