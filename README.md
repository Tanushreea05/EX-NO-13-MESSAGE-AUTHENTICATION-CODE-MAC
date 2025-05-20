# EX-NO-13-MESSAGE-AUTHENTICATION-CODE-MAC

## AIM:
To implement MESSAGE AUTHENTICATION CODE(MAC)

## ALGORITHM:

1. Message Authentication Code (MAC) is a cryptographic technique used to verify the integrity and authenticity of a message by using a secret key.

2. Initialization:
   - Choose a cryptographic hash function \( H \) (e.g., SHA-256) and a secret key \( K \).
   - The message \( M \) to be authenticated is input along with the secret key \( K \).

3. MAC Generation:
   - Compute the MAC by applying the hash function to the combination of the message \( M \) and the secret key \( K \): 
     \[
     \text{MAC}(M, K) = H(K || M)
     \]
     where \( || \) denotes concatenation of \( K \) and \( M \).

4. Verification:
   - The recipient, who knows the secret key \( K \), computes the MAC using the received message \( M \) and the same hash function.
   - The recipient compares the computed MAC with the received MAC. If they match, the message is authentic and unchanged.

5. Security: The security of the MAC relies on the secret key \( K \) and the strength of the hash function \( H \), ensuring that an attacker cannot forge a valid MAC without knowledge of the key.

## Program:
```
#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define KEY "secretkey" // Shared secret key

// Function to calculate HMAC-SHA256
void calculate_hmac(const char *message, const char *key, unsigned char *result, unsigned int *result_len) {
    HMAC(EVP_sha256(), key, strlen(key), (const unsigned char *)message, strlen(message), result, result_len);
}

int main() {
    char message[256];
    unsigned char mac_sent[EVP_MAX_MD_SIZE];
    unsigned char mac_received[EVP_MAX_MD_SIZE];
    unsigned int mac_len_sent, mac_len_received;

    // Input message from user
    printf("Enter the message: ");
    fgets(message, sizeof(message), stdin);
    message[strcspn(message, "\n")] = '\0'; // Remove newline character

    // Sender generates HMAC
    calculate_hmac(message, KEY, mac_sent, &mac_len_sent);

    printf("Generated MAC (sent): ");
    for (unsigned int i = 0; i < mac_len_sent; i++) {
        printf("%02x", mac_sent[i]);
    }
    printf("\n");

    // Receiver recalculates HMAC
    calculate_hmac(message, KEY, mac_received, &mac_len_received);

    printf("Calculated MAC (received): ");
    for (unsigned int i = 0; i < mac_len_received; i++) {
        printf("%02x", mac_received[i]);
    }
    printf("\n");

    // Verify MACs
    if (mac_len_sent == mac_len_received && memcmp(mac_sent, mac_received, mac_len_sent) == 0) {
        printf("Message is authentic.\n");
    } else {
        printf("Message integrity check failed.\n");
    }

    return 0;
}
```


## Output:

![Screenshot 2025-05-20 215554](https://github.com/user-attachments/assets/31b69123-0959-44f4-a0ab-89001db35fe1)

## Result:
The program is executed successfully.
