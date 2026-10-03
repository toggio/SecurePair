/*
 * SecurePair v. 0.5.0 - 03/10/2026
 *
 * Cryptographically secure pairing and communication between ESP32 boards:
 * pair through a single standard LED with the LX.25 protocol, or over
 * ESP-NOW and LoRa.
 *
 * Copyright (C) 2026 under Apache License, Version 2.0
 *
 * @author Luca Soltoggio
 * https://www.lucasoltoggio.it
 * https://github.com/toggio/SecurePair
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * Everything for pairing with PacketLED: the transport, the displays, the
 * button, NVS storage, SecureLink and the Serial log (ui/PairingLog.h). Radio
 * transports have their own headers (transport/EspNowTransport.h,
 * transport/LoRaTransport.h).
 *
 *   ArduinoLedPhy phy(anode, cathode);
 *   PacketLED led(phy);
 *   PacketLedTransport optical(led);
 *   LedDisplay display(optical);              // code and status on the same LED
 *   NvsPairStorage storage;
 *   SecurePair pairing(optical, storage, display, display);
 *   SecureLink channel(pairing);              // encrypted messages after pairing
 */

#pragma once

#include "SecureLink.h"
#include "SecurePair.h"
#include "storage/NvsPairStorage.h"
#include "transport/PacketLedTransport.h"
#include "ui/ButtonInput.h"
#include "ui/GpioLedSink.h"
#include "ui/LedDisplay.h"
#include "ui/PairingLog.h"
#include "ui/SerialCodeDisplay.h"
#include "ui/RgbLedDisplay.h"

using namespace securepair;
