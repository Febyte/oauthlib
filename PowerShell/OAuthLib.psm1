#requires -PSEdition Core

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

enum JwtAlgorithm { ES256; ES384; ES512; RS256; RS384; RS512 }

function New-ClientAssertion
{
	[CmdletBinding()]
	Param($ClientId, $TokenEndpointUri, $Pem, [JwtAlgorithm] $Algorithm = 'RS256')

	Begin
	{
		$HeaderText = @{alg = $Algorithm.ToString(); typ = 'JWT'} | ConvertTo-Json -Compress
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

		$HashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::new('SHA' + $Algorithm.ToString().Substring(2))

		switch ($Algorithm.ToString().Substring(0, 2))
		{
			'RS'
			{
				$AsymmetricAlgorithm = [System.Security.Cryptography.RSA]::Create()
				$SignatureFormat = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
			}

			'ES'
			{
				$AsymmetricAlgorithm = [System.Security.Cryptography.ECDsa]::Create()
				$SignatureFormat = [System.Security.Cryptography.DSASignatureFormat]::IeeeP1363FixedFieldConcatenation
			}
		}

		$AsymmetricAlgorithm.ImportFromPem($Pem)
		$SignatureBytes = $AsymmetricAlgorithm.SignData($SignaturePayloadBytes, $HashAlgorithm, $SignatureFormat)
		$AsymmetricAlgorithm.Dispose()

		$SignatureEncoded = ConvertTo-Base64Url -InputObject $SignatureBytes

		"${SignaturePayloadText}.${SignatureEncoded}"
	}
}

Export-ModuleMember -Function 'New-ClientAssertion'
