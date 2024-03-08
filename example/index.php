<?php


// Require dependencies
require_once __DIR__ . "/vendor/autoload.php";

// Use secp256k1-zkp
use Nicolasflamel\Secp256k1Zkp\Secp256k1Zkp;


// Initialize secp256k1-zkp
$secp256k1Zkp = new Secp256k1Zkp();

// Display message
echo "Validating private key" . PHP_EOL;

// Check if private key isn't valid
if($secp256k1Zkp->isValidPrivateKey(hex2bin("8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88")) === FALSE) {

	// Display message
	echo "Private key isn't valid" . PHP_EOL;
}

// Otherwise
else {

	// Display message
	echo "Private key is valid" . PHP_EOL;
}

// Display message
echo "Getting public key" . PHP_EOL;

// Check if getting public key failed
$publicKey = $secp256k1Zkp->getPublicKey(hex2bin("8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88"));
if($publicKey === FALSE) {

	// Display message
	echo "Getting public key failed" . PHP_EOL;
}

// Otherwise
else {

	// Display message
	echo "Public key: " . bin2hex($publicKey) . PHP_EOL;
}

// Display message
echo "Adding private keys" . PHP_EOL;

// Check if adding private keys failed
$privateKeySum = hex2bin("8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88");
if($secp256k1Zkp->addPrivateKeys($privateKeySum, hex2bin("7f64b1861b9139c0601f637957826da80bb3773adbc8c70265a0c3edb6fda33b")) === FALSE) {

	// Display message
	echo "Adding private keys failed" . PHP_EOL;
}

// Otherwise
else {

	// Display message
	echo "Private key sum: " . bin2hex($privateKeySum) . PHP_EOL;
}

// Display message
echo "Getting blinding factor" . PHP_EOL;

// Check if getting blinding factor failed
$blindingFactor = $secp256k1Zkp->getBlindingFactor(hex2bin("8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88"), "123456789");
if($blindingFactor === FALSE) {

	// Display message
	echo "Getting blinding factor failed" . PHP_EOL;
}

// Otherwise
else {

	// Display message
	echo "Blinding factor: " . bin2hex($blindingFactor) . PHP_EOL;
}

// Display message
echo "Getting commitment" . PHP_EOL;

// Check if getting commitment failed
$commitment = $secp256k1Zkp->getCommitment(hex2bin("8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88"), "123456789");
if($commitment === FALSE) {

	// Display message
	echo "Getting commitment failed" . PHP_EOL;
}

// Otherwise
else {

	// Display message
	echo "Commitment: " . bin2hex($commitment) . PHP_EOL;
}

// Display message
echo "Getting Bulletproof" . PHP_EOL;

// Check if getting Bulletproof failed
$bulletproof = $secp256k1Zkp->getBulletproof(hex2bin("08883a3f816419d4ce5bf44e320c24c5b09b0621c70fb780d7a35c86570bd354"), "123456789", hex2bin("74265668b4c2d901b5835de953f3ba1e1d7ce88b7e8ca89e6256145404aac330"), hex2bin("583f58e1515282cfd576319867afb4f612461993c0061a344b89e13056725eab"), hex2bin("000000021cadecb940302338354182ee67a213ba"));
if($bulletproof === FALSE) {

	// Display message
	echo "Getting Bulletproof failed" . PHP_EOL;
}

// Otherwise
else {

	// Display message
	echo "Bulletproof: " . bin2hex($bulletproof) . PHP_EOL;
}

// Display message
echo "Getting private nonce" . PHP_EOL;

// Check if getting private nonce failed
$privateNonce = $secp256k1Zkp->getPrivateNonce();
if($privateNonce === FALSE) {

	// Display message
	echo "Getting private nonce failed" . PHP_EOL;
}

// Otherwise
else {

	// Display message
	echo "Private nonce: " . bin2hex($privateNonce) . PHP_EOL;
}

// Display message
echo "Combining public keys" . PHP_EOL;

// Check if combining public keys failed
$combinedPublicKey = $secp256k1Zkp->combinePublicKeys([hex2bin("03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951"), hex2bin("033c44db7d8accfb8d89ada18934c4e5daf9902df8638a3e959d8d57aa6ca977cd"), hex2bin("03011d606ad1bd8470d1b6dbf6cb5eae25e42ea1b55915a0899b5a26020c59bd6f")]);
if($combinedPublicKey === FALSE) {

	// Display message
	echo "Combining public keys failed" . PHP_EOL;
}

// Otherwise
else {

	// Display message
	echo "Combined public key: " . bin2hex($combinedPublicKey) . PHP_EOL;
}

// Display message
echo "Getting partial single-signer signature" . PHP_EOL;

// Check if getting partial single-signer signature failed
$partialSingleSignerSignature = $secp256k1Zkp->getPartialSingleSignerSignature(hex2bin("8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88"), hex2bin("10f3f976ecfd891b95ac8dddec7ca41685f5e5b034facba4a3ef8c3d319fea54"), hex2bin("e770cbe631b86e65417355157d4696c0a9eff485a8f0a0b005a4e86e5e31f9c9"), hex2bin("02500d2963a767c6be0121b2ca0350f54b37473be066a2d30dbbc4065d5b1fee41"), hex2bin("03fdfbccfaecc71ce664b2e03b8fb535ef8497ea743a0d2644cfb267524b6c7cee"));
if($partialSingleSignerSignature === FALSE) {

	// Display message
	echo "Getting partial single-signer signature failed" . PHP_EOL;
}

// Otherwise
else {

	// Display message
	echo "Partial single-signer signature: " . bin2hex($partialSingleSignerSignature) . PHP_EOL;
}


?>
