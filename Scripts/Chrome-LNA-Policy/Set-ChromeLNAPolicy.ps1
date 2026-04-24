<#
.SYNOPSIS
  Enforce Chrome Local Network Access (LNA) policy and allow specific origins.
.DESCRIPTION
  Sets Chrome enterprise policy to enable LocalNetworkAccessRestrictions and
  allows specified public origins to initiate local network requests.
.NOTES
  Run as Administrator. Restart Chrome after applying.
  Edit the $AllowedOrigins array below before deploying.
#>

# === EDIT THESE ORIGINS BEFORE DEPLOYING ===
# Add your allowed origins below using origin-only format (scheme + host)
$AllowedOrigins = @(
  'https://your-app.example.com'        # Replace with your production origin
  # 'https://your-app.example.com/path' # Optional: path-specific, if required
  # 'https://staging.example.com'       # Optional: staging origin
)

# === POLICY PATHS ===
$ChromePolicyRoot = 'HKLM:\SOFTWARE\Policies\Google\Chrome'
$AllowedListKey   = Join-Path $ChromePolicyRoot 'LocalNetworkAccessAllowedForUrls'
$LnaToggleName    = 'LocalNetworkAccessRestrictionsEnabled'

Write-Host "Creating/ensuring policy keys..." -ForegroundColor Cyan

# Ensure base keys exist
New-Item -Path $ChromePolicyRoot -Force | Out-Null
New-Item -Path $AllowedListKey -Force | Out-Null

# Enable Local Network Access restrictions (1 = enabled)
New-ItemProperty -Path $ChromePolicyRoot -Name $LnaToggleName -PropertyType DWord -Value 1 -Force | Out-Null

# Clear existing numbered entries (comment out to append instead)
(Get-Item -Path $AllowedListKey).GetValueNames() | ForEach-Object {
  Remove-ItemProperty -Path $AllowedListKey -Name $_ -ErrorAction SilentlyContinue
}

# Write allowlist entries as numbered REG_SZ values: 1, 2, 3...
$index = 1
foreach ($origin in $AllowedOrigins) {
    New-ItemProperty -Path $AllowedListKey -Name $index -PropertyType String -Value $origin -Force | Out-Null
    $index++
}

# Verify results
Write-Host "`nEffective policy values:" -ForegroundColor Green
Get-ItemProperty -Path $ChromePolicyRoot | Select-Object LocalNetworkAccessRestrictionsEnabled
Get-ItemProperty -Path $AllowedListKey | Select-Object * | Format-List

Write-Host "`nDone. Restart Chrome and browse to chrome://policy to confirm policies are applied (Source: Platform)." -ForegroundColor Yellow
