#!/bin/bash
################################################################################################################
# This script can be used to validate that the Sovereign Keys API is working correctly.                        #
#                                                                                                              #
# It MUST be called from an EC2 instance in a VPC onboarded with Sovereign Keys, meaning:                      #
#     - the VPC MUST have an execute-endpoint VPC endpoint (the API Gateway endpoint)                          #
#     - the AWS account MUST contain a role for Sovereign Keys to use, allowing ec2:DescribeInstances          #
#     - the Sovereign Keys DynamoDB infos table MUST contain an item for the VPC ID, referencing the Role ARN  #
# All those requirements are already fullfiled for the "dummy" customer VPC                                    #
#                                                                                                              #
# The test is relatively straight-forward:                                                                     #
#     - Retrieve the Sovereign Keys Public Signing key                                                         #
#     - Create an RSA4096 key pair                                                                             #
#     - Call the "generate-secret" Sovereign Keys API                                                          #
#     - Verify the result blobs are signed by the Sovereign Keys Public Signing key                            #
#     - Store the AES wrapped secret: wrapped_secret1                                                          #
#     - Extract the actual secret from the RSA wrapped secret: secret_v1                                       #
#     - Create another RSA4096 key pair                                                                        #
#     - Call the "convert-secret" Sovereign Keys API                                                           #
#     - Verify the result blob is signed by the Sovereign Keys Public Signing key                              #
#     - Store the AES wrapped secret: wrapped_secret2                                                          #
#     - Create another RSA4096 key pair                                                                        #
#     - Call the "decrypt-secret" Sovereign Keys API from wrapped_secret2                                      #
#     - Verify the result blob are signed by the Sovereign Keys Public Signing key                             #
#     - Extract the actual secret from the RSA wrapped secret: secret_v2                                       #
#     - Verify that secret1 and secret2 are IDENTICAL                                                          #
#     - If they are, print that the test was succesful, if not signal a failure                                #
#                                                                                                              #
# This test DOES validate the workflow if the API, meaning it CANNOT be succesful if the API is FAULTY for     #
# some reason.                                                                                                 #
################################################################################################################

if [ -z "$1" ] ; then
    echo "Usage $0 <api base URL>"
    exit 2
fi

BASE_URL=$1
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)

cleanup () {
    # Display and remove
    ls -lh ec_pub_key.pem enc_secret.bin enc_secret.sig wrap_secret1.bin wrap_secret1.sig secret.bin enc_secret2.bin enc_secret2.sig wrap_secret2.bin wrap_secret2.sig secret_retrieve.bin
    rm -f ec_pub_key.pem enc_secret.bin enc_secret.sig wrap_secret1.bin wrap_secret1.sig secret.bin enc_secret2.bin enc_secret2.sig wrap_secret2.bin wrap_secret2.sig secret_retrieve.bin
}

fail () {
    echo
    echo
    echo
    echo '/!\/!\/!\/!\ TEST FAILED /!\/!\/!\/!\'
    cleanup
    echo '/!\/!\/!\/!\ TEST FAILED /!\/!\/!\/!\'
    exit 1
}

success () {
    echo
    echo
    echo
    echo "Secrets match!!!"
    echo "TEST SUCCEED"
    cleanup
    echo "TEST SUCCEED"
    exit 0
}

echo "#####################################################"
echo "#          RETRIEVE THE PUBLIC SIGNING KEY          #"
echo "#####################################################"
# Retrieve EC pub key
echo Retrieve the SK API signing public key 
RES=$(curl -H "Authorization: osef" -H "Content-Type: application/json" -X GET $BASE_URL/public-signing-key 2>/dev/null)
cat > ec_pub_key.pem << EOF
-----BEGIN PUBLIC KEY-----
$(echo $RES | jq -r .public_key)
-----END PUBLIC KEY-----
EOF
echo

echo "#####################################################"
echo "#               GENERATE A NEW SECRET               #"
echo "#####################################################"
# Generate a new secret
# Generate RSA key
echo Generating a RSA-4096 key pair
openssl genrsa -passout pass:Password -aes256 -out tmp.pem 4096 &>/dev/null
# Extract pub key
echo Retrieving the public key
PUB_KEY=$(openssl rsa -in tmp.pem -outform DER -pubout -passin pass:Password | base64 -w0)
# Ask for a new secret
echo Calling the SK API: encryption/$INSTANCE_ID/generate-secret
RES=$(curl -H "Authorization: osef" -H "Content-Type: application/json" -X POST -d "{\"rsa_wrapping_key\": \"$PUB_KEY\", \"volume_uuid\": \"AZERTU-ZERTYUI-ZERTYUI-ZERTYU\"}" $BASE_URL/encryption/$INSTANCE_ID/generate-secret 2>/dev/null)
# Store the encrypted secret
echo Storing the AES256 wrapped secret
echo $RES | jq -r .encrypted_secret | base64 -d > enc_secret.bin
# Store the encrypted secret signature
echo Storing the AES256 wrapped secret signature
echo $RES | jq -r .encrypted_secret_signature | base64 -d > enc_secret.sig
# Verify encrypted secret signature
echo Verifying the AES256 wrapped secret signature
if ! openssl dgst -sha256 -verify ec_pub_key.pem -signature enc_secret.sig enc_secret.bin ; then
    fail
fi
# Store the wrapped secret
echo Storing the RSA wrapped blob
echo $RES | jq -r .wrapped_secret | base64 -d > wrap_secret1.bin
# Store the wrapped secret signature
echo Storing the RSA wrapped blob signature
echo $RES | jq -r .wrapped_secret_signature | base64 -d > wrap_secret1.sig
# Verify wrapped secret signature
echo Verifying the RSA wrapped secret signature
if ! openssl dgst -sha256 -verify ec_pub_key.pem -signature wrap_secret1.sig wrap_secret1.bin ; then
    fail
fi
# Unwrap the wraped secret
echo Retrieve the secret_v1 from the RSA wrapped blob using the private RSA key
openssl pkeyutl -decrypt -in wrap_secret1.bin -inkey tmp.pem -passin pass:Password -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -out secret.bin
# Remove RSA key
echo Removing the RSA-4096 key pair
rm -f tmp.pem
echo


echo "#####################################################"
echo "#     CONVERT THE PREVIOUSLY GENERATED SECRET       #"
echo "#####################################################"
# Convert the secret
# Encode the encrypted secret
echo Encoding the previously stored AES256 wrapped secret
ENC_SECRET=$(base64 -w0 enc_secret.bin)
echo Calling the SK API: encryption/$INSTANCE_ID/convert-secret
RES=$(curl -sf -H "Authorization: Custom" -H "Content-Type: application/json" -X POST -d "{\"encrypted_secret\": \"$ENC_SECRET\", \"source_instance_id\": \"$INSTANCE_ID\", \"volume_uuid\": \"AZERTU-ZERTYUI-ZERTYUI-ZERTYU\"}" $BASE_URL/encryption/$INSTANCE_ID/convert-secret 2>/dev/null)
# Store the encrypted secret
echo Storing the AES256 wrapped secret
echo $RES | jq -r .encrypted_secret | base64 -d > enc_secret2.bin
# Store the encrypted secret signature
echo Storing the AES256 wrapped secret signature
echo $RES | jq -r .encrypted_secret_signature | base64 -d > enc_secret2.sig
# Verify encrypted secret signature
echo Verifying the AES256 wrapped secret signature
if ! openssl dgst -sha256 -verify ec_pub_key.pem -signature enc_secret2.sig enc_secret2.bin ; then
    fail
fi
echo

echo "#####################################################"
echo "#     DECRYPT THE PREVIOUSLY CONVERTED SECRET       #"
echo "#####################################################"
# Decrypt the secret
# Generate RSA key
echo Generating a new RSA-4096 key pair
openssl genrsa -passout pass:Password -aes256 -out tmp.pem 4096 &>/dev/null
# Extract pub key
echo Retrieving the public key
PUB_KEY=$(openssl rsa -in tmp.pem -outform DER -pubout -passin pass:Password | base64 -w0)
# Encode the encrypted secret
echo Encoding the previously stored AES256 wrapped secret
ENC_SECRET=$(base64 -w0 enc_secret2.bin)
echo Calling the SK API: encryption/$INSTANCE_ID/decrypt-secret
RES=$(curl -H "Authorization: osef" -H "Content-Type: application/json" -X POST -d "{\"encrypted_secret\": \"$ENC_SECRET\", \"rsa_wrapping_key\": \"$PUB_KEY\", \"volume_uuid\": \"AZERTU-ZERTYUI-ZERTYUI-ZERTYU\"}" $BASE_URL/encryption/$INSTANCE_ID/decrypt-secret 2>/dev/null)
# Store the wrapped secret
echo Storing the RSA wrapped blob
echo $RES | jq -r .wrapped_secret | base64 -d > wrap_secret2.bin
# Store the wrapped secret signature
echo Storing the RSA wrapped blob signature
echo $RES | jq -r .wrapped_secret_signature | base64 -d > wrap_secret2.sig
# Verify wrapped secret signature
echo Verifying the RSA wrapped secret signature
if ! openssl dgst -sha256 -verify ec_pub_key.pem -signature wrap_secret2.sig wrap_secret2.bin ; then
    fail
fi
# Unwrap the wraped secret
echo Retrieve the secret_v2 from the RSA wrapped blob using the private RSA key
openssl pkeyutl -decrypt -in wrap_secret2.bin -inkey tmp.pem -passin pass:Password -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -out secret_retrieve.bin
# Remove RSA key
echo Removing the RSA-4096 key pair
rm -f tmp.pem
echo

echo "#####################################################"
echo "# VERIFY THE 2 VERSIONS OF THE SECRET ARE IDENTICAL #"
echo "#####################################################"
echo Verifying secret_v1 and secret_v2 match
if [ $(stat -c %s secret.bin) -eq 32 ] && diff secret.bin secret_retrieve.bin ; then
    success
else
    fail
fi
