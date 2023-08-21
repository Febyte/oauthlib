function ConvertTo-Base64Url
{
	[CmdletBinding()]
	Param($InputObject, [switch]$AsPlainText)
	
	if ($AsPlainText)
	{
		$InputObject = [System.Text.Encoding]::UTF8.GetBytes($InputObject)
	}
	
	$Base64String = [Convert]::ToBase64String($InputObject)
	
	$Base64String = $Base64String.Split('=')[0]
	$Base64String.Replace('+', '-').Replace('/', '_')
}

function New-ClientAssertion
{
	[CmdletBinding()]
	Param($ClientId, $TokenEndpointUri, $Pem)
	
	Begin
	{
		$HeaderText = @{alg = 'RS256'; typ = 'JWT'} | ConvertTo-Json -Compress
		$HeaderEncoded = ConvertTo-Base64Url -InputObject $HeaderText -AsPlainText
	}
	
	Process
	{
		$Now = [DateTime]::UtcNow
		$Epoch = [DateTime]::new(1970, 01, 01)
		
		$NotBefore = ($Now.AddMinutes(-5) - $Epoch).TotalSeconds -as [long]
		$ExpiresAt = ($Now.AddMinutes(5) - $Epoch).TotalSeconds -as [long]
		
		$Payload = @{
			sub = $ClientId
			jti = [Guid]::NewGuid()
			nbf = $NotBefore
			exp = $ExpiresAt
			iss = $ClientId
			aud = $TokenEndpointUri
		}
		
		$PayloadText = $Payload | ConvertTo-Json -Compress
		$PayloadEncoded = ConvertTo-Base64Url -InputObject $PayloadText -AsPlainText
		
		$SignaturePayloadText = "${HeaderEncoded}.${PayloadEncoded}"
		$SignaturePayloadBytes = [System.Text.Encoding]::UTF8.GetBytes($SignaturePayloadText)
		
		$Rsa = [System.Security.Cryptography.RSA]::Create()
		$Rsa.ImportFromPem($Pem)
		$SignatureBytes = $Rsa.SignData($SignaturePayloadBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
		$Rsa.Dispose()
		
		$SignatureEncoded = ConvertTo-Base64Url -InputObject $SignatureBytes
		
		"${SignaturePayloadText}.${SignatureEncoded}"
	}
}

Export-ModuleMember -Function 'New-ClientAssertion'
