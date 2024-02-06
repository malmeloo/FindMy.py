"""
Example showing how to retrieve the primary key of your own AirTag
(or any other FindMy-accessory).
This key can be used to retrieve the device's location for a single day.
"""

from findmy import FindMyAccessory

# PUBLIC key that the accessory is broadcasting or has previously broadcast.
# For nearby devices, you can use `device_scanner.py` to find it.
LOOKUP_KEY = "9J5sdEARfh6h0Hr3anfNjy+vnIwETaUodv73ZA=="

# PRIVATE master key. 28 (?) bytes.
MASTER_KEY = b""

# "Primary" shared secret. 32 bytes.
SKN = b""

# "Secondary" shared secret. 32 bytes.
SKS = b""

# Lookahead in time slots. Each time slot is 15 minutes.
# Should be AT LEAST the time that has passed since you paired the accessory!
MAX_LOOKAHEAD = 7 * 24 * 4


def main() -> None:
    airtag = FindMyAccessory(MASTER_KEY, SKN, SKS)

    for i in range(MAX_LOOKAHEAD):
        prim_key, sec_key = airtag.keys_at(i)
        if LOOKUP_KEY == prim_key.adv_key_b64 or LOOKUP_KEY == prim_key.adv_key_b64:
            print(f"KEY FOUND!!")
            print(f"This key was found at index {i}."
                  f" It was likely paired approximately {i * 15} minutes ago")
            print()
            print("KEEP THE BELOW KEY SECRET! IT CAN BE USED TO RETRIEVE THE DEVICE'S LOCATION!")
            if LOOKUP_KEY == prim_key.adv_key_b64:
                print(f"PRIMARY key: {prim_key.private_key_b64}")
            else:
                print(f"SECONDARY key: {sec_key.private_key_b64}")
    else:
        print("No match found! :(")
        return


if __name__ == '__main__':
    main()
