<#
.SYNOPSIS
    Internal function for searching events with a keyed flat Event Data structure.
.DESCRIPTION
    Builds and executes a dynamic XML filter to query Windows Event Logs where event data
    is stored in a structured XML format under the UserData > EventXML node. It supports filtering
    by Event ID, provider name and custom fields within the EventXML structure. It can query local logs,
    remote systems or `.evtx` files and supports logic inversion and suppression filtering.
.EXAMPLE
    Search-EventLogEventXML -EventId 10016 -ParamHash @{ Path = 'C:\Logs\System.evtx'; Provider = 'Microsoft-Windows-DistributedCOM'; AppID = '{D63B10C5-BB46-4990-A94F-E40B9D520160}' }
    Searches a local `.evtx` file for DCOM permission events with a specific AppID.
.EXAMPLE
    Search-EventLogEventXML -EventId 20001 -ParamHash @{ ComputerName = 'Server01'; Provider = 'CustomApp'; UserName = 'jdoe' }
    Queries a remote system for custom application events where the UserName field in EventXML is 'jdoe'.
.EXAMPLE
    Search-EventLogEventXML -EventId 30001 -ParamHash @{ Path = 'C:\Logs\App.evtx'; Provider = 'MyApp'; Suppress = $true; Action = 'Delete' }
    Searches for events from 'MyApp' excluding those where the Action field in EventXML is 'Delete'.
#>
function Search-EventLogEventXML {
    [CmdletBinding()]
    param (
        # Parameters of cmdlet using this helper function.
        $ParamHash,

        # Event Id to filter on
        [int[]]
        $EventId,

        # Record type to output.
        [string]
        $RecordType,

        # Event Log Provider.
        [string]
        $Provider
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
            $SelectFilter = "`n*[System/Provider[@Name='$($Provider)'] and ($($idFilter))] "
        } else {
            $SelectFilter = "`n(*[System/Provider[@Name='$($Provider)'] and (System/EventID=$($EventId))] )"
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
                       $filter = $filter + "`n or *[UserData[EventXML[($($Param)='$($val)')]]]"
                    } else {
                        if ($Params -contains 'Suppress') {
                            $filter = $filter + "`n (*[UserData[EventXML[($($Param)='$($val)')]]]"
                        } else {
                            if ($filterBlockCount -gt 0) {
                                $filter = $filter + "`n $( $logicOperator ) (*[UserData[EventXML[($($Param)='$($val)')]]]"
                            } else {
                                $filter = $filter + "`n and (*[UserData[EventXML[($($Param)='$($val)')]]]"
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
       switch ($Params) {
           'ComputerName' {
               $ComputerName | ForEach-Object {
                   if ($null -eq $Credential) {
                       if ($MaxEvents -gt 0) {
                           Get-WinEvent -FilterXml $BaseFilter -MaxEvents $MaxEvents -ComputerName $_ -ErrorAction SilentlyContinue | ConvertFrom-EventEventXMLRecord
                       } else {
                           Get-WinEvent -FilterXml $BaseFilter -ComputerName $_ -ErrorAction SilentlyContinue | ConvertFrom-EventEventXMLRecord
                       }
                   } else {
                       if ($MaxEvents -gt 0) {
                           Get-WinEvent -FilterXml $BaseFilter -MaxEvents $MaxEvents -ComputerName $_ -Credential $Credential -ErrorAction SilentlyContinue | ConvertFrom-EventEventXMLRecord
                       } else {
                           Get-WinEvent -FilterXml $BaseFilter -ComputerName $_ -Credential $Credential -ErrorAction SilentlyContinue | ConvertFrom-EventEventXMLRecord
                       }
                   }
               }
           }
           Default {
               if ($MaxEvents -gt 0) {
                   Get-WinEvent -FilterXml $BaseFilter -MaxEvents $MaxEvents -ErrorAction SilentlyContinue | ConvertFrom-EventEventXMLRecord
               } else {
                   Get-WinEvent -FilterXml $BaseFilter -ErrorAction SilentlyContinue | ConvertFrom-EventEventXMLRecord
               }
           }
       }
   }

    end {
    }
}
