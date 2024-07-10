pragma circom 2.1.5;

include "@zk-email/zk-regex-circom/circuits/common/from_addr_regex.circom";
include "@zk-email/circuits/email-verifier.circom";
include "@zk-email/circuits/utils/regex.circom";
include "./ig-mail.circom";


/// @title IgMailTransferVerifier
/// @notice Circuit to verify input email matches Twitter password reset email, and extract the username
/// @param maxHeadersLength Maximum length for the email header.
/// @param maxBodyLength Maximum length for the email body.
/// @param n Number of bits per chunk the RSA key is split into. Recommended to be 121.
/// @param k Number of chunks the RSA key is split into. Recommended to be 17.
/// @param exposeFrom Flag to expose the from email address (not necessary for verification). We don't expose `to` as its not always signed.
/// @input emailHeader Email headers that are signed (ones in `DKIM-Signature` header) as ASCII int[], padded as per SHA-256 block size.
/// @input emailHeaderLength Length of the email header including the SHA-256 padding.
/// @input pubkey RSA public key split into k chunks of n bits each.
/// @input signature RSA signature split into k chunks of n bits each.
/// @input emailBody Email body after the precomputed SHA as ASCII int[], padded as per SHA-256 block size.
/// @input emailBodyLength Length of the email body including the SHA-256 padding.
/// @input bodyHashIndex Index of the body hash `bh` in the emailHeader.
/// @input precomputedSHA Precomputed SHA-256 hash of the email body till the bodyHashIndex.
/// @input twitterUsernameIndex Index of the Twitter username in the email body.
/// @input address ETH address as identity commitment (to make it as part of the proof).
/// @output pubkeyHash Poseidon hash of the pubkey - Poseidon(n/2)(n/2 chunks of pubkey with k*2 bits per chunk).
template IgMailTransferVerifier(maxHeadersLength, maxBodyLength, n, k, exposeFrom) {
    assert(exposeFrom < 2);

    signal input emailHeader[maxHeadersLength];
    signal input emailHeaderLength;
    signal input pubkey[k];
    signal input signature[k];
    signal input emailBody[maxBodyLength];
    signal input emailBodyLength;
    signal input bodyHashIndex;
    signal input precomputedSHA[32];
    // signal input twitterUsernameIndex;
    signal input igUsernameIndex;
    signal input oldMailIndex;
    signal input newMailIndex;
    signal input address; // we don't need to constrain the + 1 due to https://geometry.xyz/notebook/groth16-malleability


    signal output pubkeyHash;
    // signal output twitterUsername;
    signal output igUsername;

    component EV = EmailVerifier(maxHeadersLength, maxBodyLength, n, k, 0);
    EV.emailHeader <== emailHeader;
    EV.pubkey <== pubkey;
    EV.signature <== signature;
    EV.emailHeaderLength <== emailHeaderLength;
    EV.bodyHashIndex <== bodyHashIndex;
    EV.precomputedSHA <== precomputedSHA;
    EV.emailBody <== emailBody;
    EV.emailBodyLength <== emailBodyLength;

    pubkeyHash <== EV.pubkeyHash;


    // FROM HEADER REGEX: 736,553 constraints
    if (exposeFrom) {
        signal input fromEmailIndex;

        signal (fromEmailFound, fromEmailReveal[maxHeadersLength]) <== FromAddrRegex(maxHeadersLength)(emailHeader);
        fromEmailFound === 1;

        var maxEmailLength = 255;

        signal output fromEmailAddrPacks[9] <== PackRegexReveal(maxHeadersLength, maxEmailLength)(fromEmailReveal, fromEmailIndex);
    }

    signal (igFound, mailReveal[maxBodyLength], usernameReveal[maxBodyLength]) <== IgMail(maxBodyLength)(emailBody);
    igFound === 1;

    var maxIgUsernameLength = 30;
    signal igUsernamePacks[1] <== PackRegexReveal(maxBodyLength, maxIgUsernameLength)(usernameReveal, igUsernameIndex);

    var maxMailLength = 320;
    // // 11 because 320/31(max byte per field) <= 11
    signal output oldMailPacks[11] <== PackRegexReveal(maxBodyLength, maxMailLength)(mailReveal, oldMailIndex);
    signal output newMailPacks[11] <== PackRegexReveal(maxBodyLength, maxMailLength)(mailReveal, newMailIndex);

    igUsername <== igUsernamePacks[0];
}


component main { public [ address ] } = IgMailTransferVerifier(1024, 2432, 121, 17, 0);