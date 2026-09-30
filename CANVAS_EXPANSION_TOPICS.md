# KELLER-OS: Canvas Expansion Topics & Architectural Roadmap
**Zweck:** Ergänzungs-Katalog für das Obsidian-Canvas (`KELLER OS.canvas`)  
**Stil-Vorgabe:** Identisch zu den bestehenden Karten in der Canvas-Gruppe **`KELLER OS`**:
* **Konzept-Header / Bedrohung:** Prägnanter Titel & Bedrohungsszenario
* **Das Problem / Die Schwachstelle:** Wie der Angreifer vorgeht
* **Die Lösung & Der Algorithmus:** Architektonischer & prozeduraler Ablauf
* **Mathematische & Formale Basis:** Formeln, Invarianten, Beweisführung
* **Hardware- / Kernel-Mechanismus:** Konkrete CPU-/MMU-/Register-Ebene

---

## Übersicht der 12 neuen Themenfelder

| # | Themenfeld | Canvas-Kategorie | Kern-Mechanismus |
| :- | :--- | :--- | :--- |
| **01** | **Asymmetric Shard Routing (Vantablack Mesh)** | Keller Net / WAN | Informationstheoretische Sicherheit via Shamir & RS(2,1) |
| **02** | **Post-Quantum Hybrid Handshake (Ghost Protocol)** | Keller Auth / Crypto | ML-KEM-768/512 (Kyber) + X25519 (ECDH) |
| **03** | **ShardSec & Byzantine Tamper Isolation** | Keller Net / Driver | Per-Shard HKDF-Poly1305 & Kombinatorische Paar-Prüfung |
| **04** | **Anti-Traffic Analysis & Poisson Cover Traffic** | Keller Net / WAN | 576-Byte Wire-Quantisierung & RDRAND Jitter-Padding |
| **05** | **128-Bit Sliding Window Anti-Replay Defense** | Keller Session | Bitmasken-Verschiebung gegen Replay-Angriffe |
| **06** | **Pure-Rust ChaCha20-Poly1305 in Ring 0** | Keller Vault / Crypto | 130-Bit Finite Field ohne FPU/SIMD-Register |
| **07** | **Ring-3 Driver I/O Protection (TSS IOPB & MMIO)** | Driver Sandbox | Port-Berechtigungsbitmasken & DMA-Bouncing |
| **08** | **Capability-Gated Window Manager (Keller-WM)** | Keller GUI | Zero-Animation, private SHM-Backbuffer & InputCap |
| **09** | **Honey-Pot Decoy Authentication (Duress Mode)** | Keller Auth | ZK-Zweitidentität zur Entkopplung des echten Vaults |
| **10** | **Hardware-Entropie & RDRAND Underflow Guard** | Kernel Core | CPU-Thermisches Rauschen mit Spin-Pause-Schleife |
| **11** | **Declarative Immutability (NixOS-Prinzip)** | System Integrity | Deterministische Store-Hashes & Flucht vor State-Drift |
| **12** | **RISC-V Physical Memory Protection (PMP)** | Hardware Architecture | Open-Hardware ohne Intel ME / AMD PSP Hintertüren |

---

## Detaillierte Canvas-Karten-Vorlagen (Direkt kopierbar)

---

### Karte 01: Asymmetric Shard Routing (Vantablack Mesh)

#### [Karte 1A - Bedrohung & Problem]
```markdown
Asymmetric Shard Routing (Vantablack Mesh)

Ein passiver Abhörer (z.B. staatlicher ISP-Tap oder Funkpeilung) schneidet eine Netzwerkverbindung mit und speichert den gesamten Datenstrom zur späteren Kryptoanalyse.
```

#### [Karte 1B - Die Schwachstelle]
```markdown
Das Problem: Monolithische Leitungs-Interzeption
Herkömmliche VPNs oder TLS-Verbindungen schicken alle Pakete über denselben Provider-Knoten.
- Fällt die Verbindung aus, bricht der Socket ab
- Ein TAP an einem einzigen Transatlantikkabel sieht 100% der Chiffretexte
```

#### [Karte 1C - Die Lösung & Algorithmus]
```markdown
Die Lösung: Dual-Layer Sharding
Jede Nachricht wird in 3 Pakete zerlegt und über 3 getrennte WAN-Pfade versendet:
1. Shamir-Zerlegung: Der 256-Bit Sessionschlüssel wird in 3 Shares gesplittet (Threshold = 2)
2. Reed-Solomon (2,1): Der Payload wird in 2 Daten-Shards + 1 Paritäts-Shard zerlegt
3. Disjunkte Routen: Shard 0 (Glasfaser), Shard 1 (Mobilfunk/SDR), Shard 2 (Satellit)

Mathematische Garantie:
- Informationstheoretische Sicherheit: Ein einzelner Pfad liefert $I(\text{Secret}; \text{Share}_i) = 0$
- Zero-RTT Recovery: Kommt ein Shard durch Jamming/Verlust nicht an, rekonstruieren die anderen zwei den Plaintext ohne Neuübertragung
```

---

### Karte 02: Post-Quantum Hybrid Handshake (Ghost Protocol)

#### [Karte 2A - Bedrohung & Problem]
```markdown
Post-Quantum Hybrid Handshake (Ghost Protocol)

"Harvest-Now, Decrypt-Later" (HNDL): Angreifer archivieren heute verschlüsselten Datenverkehr, um ihn in 10-15 Jahren mit Quantencomputern via Shor-Algorithmus zu knacken.
```

#### [Karte 2B - Die Schwachstelle]
```markdown
Das Problem: Verletzlichkeit von ECDH & RSA
Klassische asymmetrische Kryptographie (RSA, Curve25519, Secp256k1) basiert auf diskreten Logarithmen oder Primfaktorzerlegung.
Ein Cryptographically Relevant Quantum Computer (CRQC) löst diese Probleme in polynomialer Zeit:
$$\mathcal{O}((\log N)^3)$$
```

#### [Karte 2C - Die Lösung & Algorithmus]
```markdown
Die Lösung: Hybride KEM-Verschachtelung
Der 960-Byte "GHOST_HANDSHAKE" kombiniert klassische Kurven mit Gitter-Kryptographie:
$$K_{\text{session}} = \text{SHA-256}\Big(\text{ECDH}(X_{\text{priv}}, X_{\text{pub}}) \;\parallel\; \text{Kyber-Decap}(C_{\text{kyber}}, \text{Kyber}_{\text{priv}})\Big)$$

1. ML-KEM-768/512 (Kyber): Basiert auf dem Module Learning With Errors (MLWE) Gitter-Problem
2. X25519 (ECDH): Schützt vor unentdeckten mathematischen Schwachstellen in neuartigen Gitter-Algorithmen
3. Ed25519: Signiert den Kyber-Vektor gegen Man-in-the-Middle Angriffe
```

---

### Karte 03: ShardSec & Byzantine Tamper Isolation

#### [Karte 3A - Bedrohung & Problem]
```markdown
ShardSec & Byzantine Tamper Isolation

Ein bösartiger Relais-Knoten im Mesh (Carrier) manipuliert gezielt einzelne Bytes eines durchlaufenden Pakets, um Integritätsprüfungen des Empfängers zu stören.
```

#### [Karte 3B - Die Schwachstelle]
```markdown
Das Problem: Verdeckte Korruption bei Erasure Coding
Bei normalem Reed-Solomon schlägt erst die Gesamtrekonstruktion fehl. Das System weiß nicht, welcher der 3 Pfade manipuliert wurde, und muss alle Daten verwerfen.
```

#### [Karte 3C - Die Lösung & Algorithmus]
```markdown
Die Lösung: ShardSec & Kombinatorische Prüfung
1. ShardSec (Default-On): Jeder RS-Shard erhält einen eigenen, via HKDF abgeleiteten Poly1305-MAC. Manipulierte Shards fliegen sofort am Ingress-Filter raus.
2. Kombinatorischer Pairwise-Test:
   - Teste Paar $(0, 1)$ — schließt Pfad 2 aus
   - Teste Paar $(0, 2)$ — schließt Pfad 1 aus
   - Teste Paar $(1, 2)$ — schließt Pfad 0 aus
3. Isolation: Das Paar mit gültigem AEAD-Tag isoliert den byzantinischen Carrier automatisch (`TAMPER REJECTED`) und routet den Pfad um.
```

---

### Karte 04: Anti-Traffic Analysis & Dynamic Entropy Jitter

#### [Karte 4A - Bedrohung & Problem]
```markdown
Anti-Traffic Analysis (Metadaten-Schutz)

Deep Packet Inspection (DPI) und Künstliche Intelligenz analysieren Paketgrößen und Zeitabstände, um trotz Verschlüsselung auf Protokolle und Nutzerverhalten zu schließen.
```

#### [Karte 4B - Die Schwachstelle]
```markdown
Das Problem: Paket-Signaturen
- Ein HTTP-GET hat eine andere Bytezahl als ein Tastaturanschlag in SSH
- Sprechpausen in VoIP erzeugen verräterische Latenz- und Längenmuster
```

#### [Karte 4C - Die Lösung & Algorithmus]
```markdown
Die Lösung: 576-Byte Quantisierung & RDRAND-Jitter
1. Feste Wire-Größe: Alle Pakete werden exakt auf 576 Bytes normiert
2. Keyed Jitter-Tail: Jedes Paket erhält ein variables Padding von $16..64$ Bytes aus dem Hardware-Entropie-Pool (`RDRAND`), das als AEAD Associated Data authentifiziert wird
3. Poisson Cover Traffic: In Leerlaufzeiten generiert der Mesh-Daemon synthetische Dummy-Pakete nach einer Poisson-Verteilung:
$$P(k \text{ Pakete in } t) = \frac{(\lambda t)^k e^{-\lambda t}}{k!}$$
```

---

### Karte 05: 128-Bit Sliding Window Anti-Replay Defense

#### [Karte 5A - Bedrohung & Problem]
```markdown
128-Bit Sliding Window Anti-Replay Defense

Ein Angreifer zeichnet ein valides, verschlüsseltes Steuerpaket auf (z.B. "Geld überweisen" oder "Session öffnen") und sendet es 5 Minuten später unverändert erneut (Replay Attack).
```

#### [Karte 5B - Die Schwachstelle]
```markdown
Das Problem: Asynchrone Mesh-Laufzeiten
Im Mesh kommen Pakete oft nicht-monoton an (Route B ist schneller als Route A). Ein simples `Counter > LastCounter` würde legitime Pakete verwerfen.
```

#### [Karte 5C - Die Lösung & Algorithmus]
```markdown
Die Lösung: KernelSessionGuard Bitmaske
Ein 128-Bit Bitmap-Fenster im Kernel speichert empfangene Counter relativ zum Maximum $v_{\text{max}}$:
1. $Counter > v_{\text{max}}$: Bitmaske shiftet um $\Delta$:
   $$\text{bitmask} = (\text{bitmask} \ll \Delta) \mid 1$$
2. $Counter \le v_{\text{max}}$: Liegt der Counter im Fenster $[v_{\text{max}}-127, v_{\text{max}}]$, prüfe:
   $$\text{if } (\text{bitmask} \ \& \ (1 \ll \text{offset})) \neq 0 \implies \text{REPLAY DETECTED!}$$
3. Zu alte Pakete ($Counter < v_{\text{max}} - 128$) werden sofort verworfen.
```

---

### Karte 06: Pure-Rust ChaCha20-Poly1305 in Ring 0

#### [Karte 6A - Bedrohung & Problem]
```markdown
Pure-Rust ChaCha20-Poly1305 in Ring 0

Standard-Krypto-Bibliotheken nutzen SIMD/AVX-Vektorregister. Im Betriebssystemkern (`Ring 0`) führt dies zu Abstürzen oder gigantischem Kontextwechsel-Overhead.
```

#### [Karte 6B - Die Schwachstelle]
```markdown
Das Problem: FPU/SSE-Register im Kernel
Das Speichern und Wiederherstellen von 512-Bit AVX-Registern bei jedem Hardware-Interrupt kostet hunderte CPU-Zyklen. Daher kompiliert der KELLER-OS Kern mit:
`-C target-feature=-mmx,-sse,-avx`
```

#### [Karte 6C - Die Lösung & Algorithmus]
```markdown
Die Lösung: 130-Bit Integer-Arithmetik (RFC 8439)
Poly1305 wird komplett über fünf 26-Bit Limbs in 32-Bit Unsigned Integers berechnet:
- Modulo $2^{130}-5$ Faltung:
  $$2^{130} \equiv 5 \pmod{2^{130}-5}$$
  Überträge aus Bit 130 werden mit 5 multipliziert und in Limb 0 addiert.
- Verification-Before-Decryption:
  Der 16-Byte MAC wird timing-sicher (`ct_eq`) geprüft, bevor ChaCha20 ein einziges Byte Plaintext anrührt.
```

---

### Karte 07: Ring-3 Driver I/O Protection (TSS IOPB & MMIO)

#### [Karte 7A - Bedrohung & Problem]
```markdown
Driver Isolation (TSS IOPB & MMIO)

Ein Hardware-Treiber (z.B. Netzwerkkarte oder USB) wird über fehlerhafte Firmware oder Malicious Packets kompromittiert.
```

#### [Karte 7B - Die Schwachstelle]
```markdown
Das Problem: Ring-0 Treiber in Windows/Linux
In monolithischen Betriebssystemen laufen Treiber im Kernel-Space. Ein Buffer-Overflow in der WLAN-Firmware gibt dem Angreifer Ring-0 Vollzugriff auf den gesamten Arbeitsspeicher.
```

#### [Karte 7C - Die Lösung & Algorithmus]
```markdown
Die Lösung: Task State Segment (TSS) I/O Bitmap
1. Treiber laufen strikt in Ring 3 (User-Space)
2. Hardware-Port-Schutz: Die CPU prüft die I/O Permission Bitmap (IOPB) im TSS:
   Ein Port-Zugriff (`inb`/`outb`) ist nur für exakt die Bits erlaubt, für die der Treiber eine Capability besitzt
3. DMA-Air-Gap: Geräte haben keinen Bus-Master DMA-Zugriff auf den Kernel; Daten werden über isolierte Ring-3 Bounce-Buffer ausgetauscht
```

---

### Karte 08: Capability-Gated Window Manager (Keller-WM)

#### [Karte 8A - Bedrohung & Problem]
```markdown
Capability-Gated Window Manager (Keller-WM)

Screen-Scraping Malware und Keylogger lesen unbemerkt Bildschirminhalte oder Passwörter anderer Fenster aus.
```

#### [Karte 8B - Die Schwachstelle]
```markdown
Das Problem: Ambient Authority in X11 / Windows GDI
Unter X11 kann jeder Client die Events aller anderen Fenster abhören (`XRecord`, `XQueryTree`). Es gibt keine echte visuelle Isolation.
```

#### [Karte 8C - Die Lösung & Algorithmus]
```markdown
Die Lösung: Ocap-Display-Server & Zero-Animation
1. Private SHM-Puffer: Jedes Fenster besitzt einen isolierten Backbuffer; andere Prozesse können ihn weder lesen noch beschreiben
2. InputFocusCap: Tastatur- und Maus-Events werden vom Kernel ausschließlich an den Prozess mit der aktiven Fokus-Capability geroutet
3. Zero-Animation & Dirty-Rect: Redraws erfolgen deterministisch ohne GPU-Shader; keine Framerate-Einbrüche, die Krypto-Aktivitäten verraten
4. Panic-Scrub: Beim Kernel-Panic wird der gesamte VRAM in Millisekunden genullt
```

---

### Karte 09: Honey-Pot Decoy Authentication (Duress Mode)

#### [Karte 9A - Bedrohung & Problem]
```markdown
Honey-Pot Decoy Authentication (Duress Mode)

"Rubber-Hose Cryptanalysis": Der Systembetreiber wird physisch zur Herausgabe des Systempassworts gezwungen.
```

#### [Karte 9B - Die Schwachstelle]
```markdown
Das Problem: Keine Glaubhafte Abstreitbarkeit (Plausible Deniability)
Verweigert der Nutzer das Passwort, droht physische Gewalt. Gibt er es heraus, sind alle Vault-Geheimnisse verloren.
```

#### [Karte 9C - Die Lösung & Algorithmus]
```markdown
Die Lösung: Schnorr-Zweitidentität & Schein-Sandbox
1. Decoy-Passphrase: Der Benutzer gibt ein alternatives Passwort ein
2. Zero-Knowledge Proof: Das System akzeptiert den Schnorr-Proof für die sekundäre Identität
3. Sterile Sandbox: Das System startet eine voll funktionstüchtige, plausible Desktop-Umgebung mit synthetischem Netzwerktraffic
4. Vault-Isolation: Die Speicherseiten des echten `Keller Vault` bleiben im RAM verschlüsselt und für den Prozess unsichtbar
```

---

### Karte 10: Hardware-Entropie & RDRAND Underflow Guard

#### [Karte 10A - Bedrohung & Problem]
```markdown
Hardware-Entropie & RDRAND Underflow Guard

Software-Zufallsgeneratoren (PRNGs) basieren auf vorhersagbaren Seeds oder erschöpfen ihren Entropie-Pool, wodurch Schlüssel vorhersagbar werden.
```

#### [Karte 10B - Die Schwachstelle]
```markdown
Das Problem: Der Debian OpenSSL Bug (2008)
Ein Compiler- oder Logikfehler im PRNG führt dazu, dass statt $2^{256}$ Schlüsseln nur wenige tausend Kombinationen entstehen – alle Schlüssel sind kompromittiert.
```

#### [Karte 10C - Die Lösung & Algorithmus]
```markdown
Die Lösung: CPU Silicon Thermal Noise & Spin-Wait
KELLER-OS greift direkt auf die thermische Rauschquelle des CPU-Kristalls zu:
```rust
unsafe {
    while core::arch::x86_64::_rdrand64_step(&mut val) != 1 {
        core::arch::asm!("pause");
    }
}
```
- Underflow-Schutz: Gibt die Hardware `CF=0` zurück (Entropiepool temporär leer), blockiert der Kern via `pause` in konstanter Zeit, bis echte physikalische Entropie nachgeliefert wurde.
```

---

### Karte 11: Declarative Immutability (NixOS-Prinzip)

#### [Karte 11A - Bedrohung & Problem]
```markdown
Declarative Immutability (NixOS-Prinzip)

State-Drift und verdeckte Systemmodifikationen: Über Monate schleichen sich Konfigurationsänderungen, temporäre Scripts oder Rootkits ein.
```

#### [Karte 11B - Die Schwachstelle]
```markdown
Das Problem: Mutabler State in `/etc` und `/usr`
In klassischen Unix-Systemen kann man nie mit Sicherheit sagen, ob das System exakt dem Ursprungszustand entspricht.
```

#### [Karte 11C - Die Lösung & Algorithmus]
```markdown
Die Lösung: Pure Functional System Generation
1. Declarative Spec: Das gesamte Betriebssystem ist das Resultat einer reinen mathematischen Funktion:
   $$\text{System} = f(\text{Configuration.kos})$$
2. Content-Addressed Store: Systemdateien liegen in schreibgeschützten Hash-Pfaden (`/kos/store/<hash>-package`)
3. Atomic Rollback: Ein Update schaltet lediglich einen Zeiger um. Tritt ein Fehler auf, bootet der Bootloader die vorherige Generation.
```

---

### Karte 12: RISC-V Physical Memory Protection (PMP)

#### [Karte 12A - Bedrohung & Problem]
```markdown
RISC-V Physical Memory Protection (PMP)

Proprietäre Hardware-Hintertüren auf x86-Plattformen: Intel Management Engine (ME) und AMD Platform Security Processor (PSP) laufen in "Ring -3" mit unkontrolliertem Speicherzugriff.
```

#### [Karte 12B - Die Schwachstelle]
```markdown
Das Problem: Ring -3 Microcode-Exploits
Selbst wenn der OS-Kern formal verifiziert ist, hat der Intel ME Coprozessor eigenen DMA-Zugriff auf den RAM und kann über das Netzwerk Befehle empfangen.
```

#### [Karte 12C - Die Lösung & Algorithmus]
```markdown
Die Lösung: Open Silicon & RISC-V PMP
1. Open-Source ISA: Vollständige Überprüfbarkeit des Prozessordesigns ohne geschlossenen Fremdcode
2. PMP (Physical Memory Protection): Hardware-Register in RISC-V erzwingen Sub-Page Isolation direkt im CPU-Kern:
   - Erlaubt das Definieren von isolierten Sicherheits-Zonen ohne teuren Page-Table Walk der MMU
   - Hardware-garantierte Abschirmung von Schlüsselspeichern selbst gegen privilegierte Kernel-Instruktionen
```

---

## 3. Empfohlene Anordnung im Canvas

Um das visuelle Layout deines Obsidian-Canvas beizubehalten, empfiehlt sich folgende Platzierung innerhalb der **`KELLER OS`** Gruppe:

* **Säule 1 (Netzwerk & WAN):** Karten 01 (Asymmetric Sharding), 03 (ShardSec), 04 (Anti-Traffic Analysis) $\to$ platziere sie links neben `Keller Net`.
* **Säule 2 (Kryptographie & Handshake):** Karten 02 (Ghost Handshake), 06 (Pure-Rust AEAD), 10 (Hardware-Entropie) $\to$ platziere sie unter `Keller Vault`.
* **Säule 3 (Authentifizierung & Identität):** Karten 05 (Anti-Replay Window), 09 (Honey-Pot Duress) $\to$ platziere sie unter `Keller Auth`.
* **Säule 4 (Isolation & Hardware):** Karten 07 (TSS IOPB), 08 (Keller-WM), 11 (NixOS Immutability), 12 (RISC-V PMP) $\to$ platziere sie neben `Keller Driver Sandbox`.
