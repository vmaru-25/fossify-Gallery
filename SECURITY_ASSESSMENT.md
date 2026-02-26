# Analisi di sicurezza – fossify-Gallery

## Scope e metodo
- Revisione statica della configurazione Android (manifest, build, dipendenze) e dei punti di ingresso esposti via Intent/Broadcast.
- Focus su: superficie di attacco IPC, data protection, permessi ad alto rischio, hardening build/release.

## Principali rischi individuati

### 1) Receiver esportato senza protezione (`RefreshMediaReceiver`) – **High**
**Evidenza:** il receiver è esportato e ascolta un'azione custom pubblica (`org.fossify.REFRESH_MEDIA`) senza `android:permission`. Qualsiasi app può inviare il broadcast e pilotare il path elaborato.  
**Impatto:** abuso di funzionalità interne (inquinamento DB, trigger non autorizzati, possibili DoS logici se inviati eventi in loop).  
**Remediation consigliata:**
1. Impostare `android:exported="false"` se l'uso è solo interno.
2. In alternativa, proteggere con permission `signature` dedicata.
3. Validare input (`REFRESH_PATH`) con allowlist di root/URI consentiti prima di scrivere su DB.
4. Aggiungere rate limiting/debounce lato receiver.

### 2) Receiver BOOT esposto e senza validazione action (`BootCompletedReceiver`) – **Medium/High**
**Evidenza:** receiver esportato; in `onReceive` non viene verificata l'action e parte una scansione in background.  
**Impatto:** app terze possono invocare il receiver con intent esplicito causando lavoro pesante e consumo risorse (DoS batteria/performance).
**Remediation consigliata:**
1. Verificare esplicitamente `Intent.ACTION_BOOT_COMPLETED` / `QUICKBOOT_POWERON` prima di eseguire logica.
2. Valutare `android:exported="false"` se non necessario ricevere broadcast esterni oltre quelli di sistema.
3. Introdurre throttling (es. timestamp ultimo run) per limitare trigger ravvicinati.

### 3) Backup applicativo abilitato (`allowBackup=true`) – **Medium**
**Evidenza:** nel manifest `android:allowBackup="true"`.  
**Impatto:** possibile esfiltrazione di dati applicativi su device compromessi/ADB backup legacy e restore non voluto su contesti differenti.
**Remediation consigliata:**
1. Impostare `android:allowBackup="false"` se non strettamente necessario.
2. Se va mantenuto, usare `fullBackupContent`/`dataExtractionRules` per escludere dati sensibili.

### 4) Permessi storage altamente privilegiati – **Medium**
**Evidenza:** dichiarati `MANAGE_EXTERNAL_STORAGE` e `MANAGE_MEDIA`, oltre a `requestLegacyExternalStorage="true"`.  
**Impatto:** aumenta drasticamente il blast radius in caso di bug logico/abuso intent; rischio privacy e revisione store più severa.
**Remediation consigliata:**
1. Applicare principio del minimo privilegio (scoped storage + SAF dove possibile).
2. Rendere la richiesta di permessi “just-in-time” e degradare funzionalità senza privilegi broad.
3. Pianificare deprecazione graduale di `requestLegacyExternalStorage`.

### 5) Igiene dipendenze: librerie vecchie/non mantenute – **Medium**
**Evidenza:** presenza di dipendenze storicamente sensibili a CVE o datate (es. `picasso 2.71828`, `sanselan 0.97-incubator`).
**Impatto:** superficie vulnerabile in parsing immagini/metadata e supply-chain risk.
**Remediation consigliata:**
1. Introdurre SCA automatica (OSV-Scanner/Dependency-Check/Dependabot/Renovate).
2. Sostituire librerie non mantenute o congelate con alternative supportate.
3. Definire patch policy (SLA: Critical 48h, High 7gg, Medium 30gg).

## Piano remediation (priorità)

### Sprint 0 (immediato, 1–3 giorni)
- Hardening receiver IPC:
  - blindare `RefreshMediaReceiver` (non esportato o permission signature);
  - validazione rigorosa degli extra;
  - check action in `BootCompletedReceiver`.
- Aggiungere test strumentali su intent malevoli (broadcast fuzzing di base).

### Sprint 1 (1 settimana)
- Revisione data protection:
  - decidere policy `allowBackup`;
  - introdurre `dataExtractionRules/fullBackupContent` se backup richiesto.
- Revisione permessi storage e piano di riduzione privilegi.

### Sprint 2 (2–4 settimane)
- Programma dependency hygiene:
  - SCA in CI + report CVE;
  - aggiornamento/sostituzione librerie obsolete;
  - SBOM (CycloneDX) per release.

## Checklist di controllo suggerita (CI)
- Lint/Android security lint bloccante su:
  - componenti esportati senza permission;
  - backup policy non conforme;
  - permessi ad alto rischio senza giustificazione.
- SAST (Semgrep/CodeQL) con regole Android IPC + file handling.
- SCA e fail build su CVE High/Critical non mitigate.

## Nota
Questa analisi è una valutazione statica rapida: per una postura completa servono anche test dinamici (pentest mobile, runtime instrumentation, test su content provider/URI edge-case, verifica policy Play).
