class ESCalatorIssue {
    <#
        .SYNOPSIS
        Represents a security issue identified in Active Directory Certificate Services (ADCS) environments.

        .DESCRIPTION
        This class provides a standardized structure for security issues found by ESCalator vulnerability
        scanning functions like Find-ESC4 and Find-ESC5. All Issue objects share the same properties 
        and methods for consistent analysis and processing.

        .NOTES
        This class is used internally by ESCalator functions to ensure consistent Issue object structure.
        All properties are validated during construction to maintain data integrity.
    #>

    # Core identification properties
    [string]$Forest
    [string]$Name
    [string]$DistinguishedName
    [string]$IdentityReference
    [string]$IdentityReferenceSID
    [string]$ActiveDirectoryRights
    [string]$Technique
    [string]$Subtype
    [string]$Issue

    # Optional properties for detailed analysis
    [string]$ObjectType
    [System.DirectoryServices.DirectoryEntry]$DirectoryEntry

    # Group expansion properties (null for original issues)
    [string]$ExpandedFromGroup
    [string]$ExpandedFromGroupSID
    [string]$MemberType

    # Constructor for original issues (from Find-ESC4, Find-ESC5)
    ESCalatorIssue(
        [string]$Forest,
        [string]$Name,
        [string]$DistinguishedName,
        [string]$IdentityReference,
        [string]$IdentityReferenceSID,
        [string]$ActiveDirectoryRights,
        [string]$Technique,
        [string]$Subtype,
        [string]$Issue,
        [string]$ObjectType,
        [System.DirectoryServices.DirectoryEntry]$DirectoryEntry
    ) {
        $this.Forest = $Forest
        $this.Name = $Name
        $this.DistinguishedName = $DistinguishedName
        $this.IdentityReference = $IdentityReference
        $this.IdentityReferenceSID = $IdentityReferenceSID
        $this.ActiveDirectoryRights = $ActiveDirectoryRights
        $this.Technique = $Technique
        $this.Subtype = $Subtype
        $this.Issue = $Issue
        $this.ObjectType = $ObjectType
        $this.DirectoryEntry = $DirectoryEntry
        
        # Set group expansion properties to null for original issues
        $this.ExpandedFromGroup = $null
        $this.ExpandedFromGroupSID = $null
        $this.MemberType = $null
    }

    # Constructor for expanded issues (from group membership expansion)
    ESCalatorIssue(
        [string]$Forest,
        [string]$Name,
        [string]$DistinguishedName,
        [string]$IdentityReference,
        [string]$IdentityReferenceSID,
        [string]$ActiveDirectoryRights,
        [string]$Technique,
        [string]$Subtype,
        [string]$Issue,
        [string]$ObjectType,
        [System.DirectoryServices.DirectoryEntry]$DirectoryEntry,
        [string]$ExpandedFromGroup,
        [string]$ExpandedFromGroupSID,
        [string]$MemberType
    ) {
        $this.Forest = $Forest
        $this.Name = $Name
        $this.DistinguishedName = $DistinguishedName
        $this.IdentityReference = $IdentityReference
        $this.IdentityReferenceSID = $IdentityReferenceSID
        $this.ActiveDirectoryRights = $ActiveDirectoryRights
        $this.Technique = $Technique
        $this.Subtype = $Subtype
        $this.Issue = $Issue
        $this.ObjectType = $ObjectType
        $this.DirectoryEntry = $DirectoryEntry
        $this.ExpandedFromGroup = $ExpandedFromGroup
        $this.ExpandedFromGroupSID = $ExpandedFromGroupSID
        $this.MemberType = $MemberType
    }

    # Static method to create original issue
    static [ESCalatorIssue] CreateOriginalIssue(
        [string]$Forest,
        [string]$Name,
        [string]$DistinguishedName,
        [string]$IdentityReference,
        [string]$IdentityReferenceSID,
        [string]$ActiveDirectoryRights,
        [string]$Technique,
        [string]$Subtype,
        [string]$Issue,
        [string]$ObjectType,
        [System.DirectoryServices.DirectoryEntry]$DirectoryEntry
    ) {
        return [ESCalatorIssue]::new(
            $Forest, $Name, $DistinguishedName, $IdentityReference, $IdentityReferenceSID,
            $ActiveDirectoryRights, $Technique, $Subtype, $Issue, $ObjectType, $DirectoryEntry
        )
    }

    # Static method to create expanded issue
    static [ESCalatorIssue] CreateExpandedIssue(
        [string]$Forest,
        [string]$Name,
        [string]$DistinguishedName,
        [string]$IdentityReference,
        [string]$IdentityReferenceSID,
        [string]$ActiveDirectoryRights,
        [string]$Technique,
        [string]$Subtype,
        [string]$Issue,
        [string]$ObjectType,
        [System.DirectoryServices.DirectoryEntry]$DirectoryEntry,
        [string]$ExpandedFromGroup,
        [string]$ExpandedFromGroupSID,
        [string]$MemberType
    ) {
        return [ESCalatorIssue]::new(
            $Forest, $Name, $DistinguishedName, $IdentityReference, $IdentityReferenceSID,
            $ActiveDirectoryRights, $Technique, $Subtype, $Issue, $ObjectType, $DirectoryEntry,
            $ExpandedFromGroup, $ExpandedFromGroupSID, $MemberType
        )
    }

    # Method to check if this is an expanded issue
    [bool] IsExpanded() {
        return -not [string]::IsNullOrEmpty($this.ExpandedFromGroup)
    }

    # Method to check if this is a high-risk issue
    [bool] IsHighRisk() {
        return $this.ActiveDirectoryRights -match 'GenericAll|FullControl|WriteOwner|WriteDacl|Owner'
    }

    # Method to get a summary of the issue
    [PSCustomObject] GetSummary() {
        return [PSCustomObject]@{
            Technique = $this.Technique
            Subtype = $this.Subtype
            Object = $this.Name
            Principal = $this.IdentityReference
            Rights = $this.ActiveDirectoryRights
            IsExpanded = $this.IsExpanded()
            IsHighRisk = $this.IsHighRisk()
            ExpandedFrom = $this.ExpandedFromGroup
        }
    }

    # Method to convert to hashtable (for compatibility with existing code)
    [hashtable] ToHashTable() {
        return @{
            Forest = $this.Forest
            Name = $this.Name
            DistinguishedName = $this.DistinguishedName
            IdentityReference = $this.IdentityReference
            IdentityReferenceSID = $this.IdentityReferenceSID
            ActiveDirectoryRights = $this.ActiveDirectoryRights
            Technique = $this.Technique
            Subtype = $this.Subtype
            Issue = $this.Issue
            ObjectType = $this.ObjectType
            DirectoryEntry = $this.DirectoryEntry
            ExpandedFromGroup = $this.ExpandedFromGroup
            ExpandedFromGroupSID = $this.ExpandedFromGroupSID
            MemberType = $this.MemberType
        }
    }

    # Method to convert to PSCustomObject (for compatibility with existing code)
    [PSCustomObject] ToPSCustomObject() {
        return [PSCustomObject]@{
            Forest = $this.Forest
            Name = $this.Name
            DistinguishedName = $this.DistinguishedName
            IdentityReference = $this.IdentityReference
            IdentityReferenceSID = $this.IdentityReferenceSID
            ActiveDirectoryRights = $this.ActiveDirectoryRights
            Technique = $this.Technique
            Subtype = $this.Subtype
            Issue = $this.Issue
            ObjectType = $this.ObjectType
            DirectoryEntry = $this.DirectoryEntry
            ExpandedFromGroup = $this.ExpandedFromGroup
            ExpandedFromGroupSID = $this.ExpandedFromGroupSID
            MemberType = $this.MemberType
        }
    }

    # Override ToString for better display
    [string] ToString() {
        $expandedInfo = if ($this.IsExpanded()) { " (expanded from $($this.ExpandedFromGroup))" } else { "" }
        return "$($this.Technique)-$($this.Subtype): $($this.IdentityReference) -> $($this.Name)$expandedInfo"
    }

    # Method to validate the issue object
    [bool] IsValid() {
        $requiredFields = @('Forest', 'Name', 'DistinguishedName', 'IdentityReference', 
                           'IdentityReferenceSID', 'ActiveDirectoryRights', 'Technique', 'Subtype', 'Issue')
        
        foreach ($field in $requiredFields) {
            if ([string]::IsNullOrEmpty($this.$field)) {
                Write-Warning "ESCalatorIssue validation failed: $field is null or empty"
                return $false
            }
        }
        
        # Validate technique is known
        $validTechniques = @('ESC4', 'ESC5', 'ESC1', 'ESC2', 'ESC3', 'ESC6', 'ESC7', 'ESC8', 'ESC9', 'ESC10', 'ESC11', 'ESC13', 'ESC15')
        if ($this.Technique -notin $validTechniques) {
            Write-Warning "ESCalatorIssue validation failed: Unknown technique '$($this.Technique)'"
            return $false
        }
        
        return $true
    }

    # Method to create a copy of the issue with modifications
    [ESCalatorIssue] CreateCopy([hashtable]$modifications = @{}) {
        $props = $this.ToHashTable()
        
        # Apply modifications
        foreach ($key in $modifications.Keys) {
            if ($props.ContainsKey($key)) {
                $props[$key] = $modifications[$key]
            }
        }
        
        return [ESCalatorIssue]::new(
            $props.Forest, $props.Name, $props.DistinguishedName, $props.IdentityReference,
            $props.IdentityReferenceSID, $props.ActiveDirectoryRights, $props.Technique,
            $props.Subtype, $props.Issue, $props.ObjectType, $props.DirectoryEntry,
            $props.ExpandedFromGroup, $props.ExpandedFromGroupSID, $props.MemberType
        )
    }
}