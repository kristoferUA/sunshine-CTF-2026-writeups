# Welcome Call!

SunshineCTF 2026 · forensics · author: [kristoferUA](https://github.com/kristoferUA)

The challenge provides a packet capture of a welcome call carried as RTP audio negotiated over SIP. I listened to the voice message and converted its words to the event's flag format.

Flag: `sun{thankyouforplaying}`

## Solution

### Locating the audio

The SIP exchange sets up a one-way stream from `192.0.2.10:4000` to `192.0.2.20:4002` using PCMU at 8 kHz. The recording says, “Thank you for playing.”

### Building the flag

The message gives the flag text directly. Write the spoken words in lowercase, remove the spaces, and use the SunshineCTF `sun{...}` format:

```text
Thank you for playing
        ↓ lowercase and remove spaces
thankyouforplaying
        ↓ add the event format
sun{thankyouforplaying}
```

## Reproducing the result

Open `challenge/welcomecall.pcap` in Wireshark. Choose **Telephony → RTP → RTP Streams**, select the stream, choose **Analyze**, and play it. Lowercase the spoken words, remove spaces, and wrap them in `sun{...}`.

## Repository layout

```text
README.md                             this writeup
challenge/welcomecall.pcap            supplied packet capture
```

## Result

The recovered flag is:

```text
sun{thankyouforplaying}
```
