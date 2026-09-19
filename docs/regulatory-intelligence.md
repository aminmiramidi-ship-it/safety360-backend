# Safety360 Regulatory Intelligence

Safety360 behandelt Gesetze, Verordnungen, Unfallverhütungsvorschriften, behördliche Regeln und Managementsystem-Standards als versionierte, überprüfbare Metadaten und nicht als unkontrollierten Textimport.

## Grundprinzipien

- Primärquellen vor Sekundärquellen.
- Jede Quelle trägt Behörde/Organisation, Jurisdiktion, URL, Typ, Aktivstatus und Prüfzeitpunkt.
- Jede Anforderung trägt Quellenreferenz, Version/Fassung, Geltungsstatus, Geltungszeitraum, Themengebiet, optionales Managementsystem, Inhalts-Hash und Anwendbarkeitsmetadaten.
- Änderungen werden als eigenes Change-Event mit vorherigem/neuem Hash, Detektionszeitpunkt, Review-Status und Impact-Metadaten gespeichert.
- Neue oder geänderte Anforderungen sind standardmäßig human-review-pflichtig.
- Safety360 darf keine fehlende Anwendbarkeit erfinden. Unklare Sachverhalte bleiben `unknown` und erzeugen Rückfragen.
- Geschützte Normentexte werden nicht kopiert. Für ISO/EN/DIN werden nur zulässige öffentliche Metadaten, eigene Zusammenfassungen, Referenzen und kundenseitig lizenzierte Inhalte verwendet.

## Bevorzugte Quellenfamilien

Deutschland/EU:

- Gesetze im Internet
- BAuA
- DGUV
- BMAS und zuständige Bundes-/Landesbehörden
- EUR-Lex
- EDPB/BfDI/Landesdatenschutzaufsichten für Datenschutz

Managementsysteme:

- ISO/IEC/EN/DIN-Metadaten und kundenseitig lizenzierte Normfassungen
- ISO 45001
- ISO 14001
- ISO 50001
- ISO 9001
- ISO/IEC 27001
- EN 50600

## Autopilot-Workflow

1. Quelle prüfen.
2. Fassung/Änderungsstand erkennen.
3. Normalisierte Metadaten bilden.
4. Hash mit vorhandenem Datensatz vergleichen.
5. Neue/geänderte Anforderung als Change Event speichern.
6. Relevanz zu Branche, Standort, Tätigkeit, Arbeitsmittel, Gefahrstoff, Rolle, Managementsystem und Jurisdiktion bewerten.
7. `unknown`-Felder und Evidenzlücken ausweisen.
8. Impact-Vorschlag auf bestehende Safety360-Artefakte erzeugen.
9. Fachliche/rechtliche Freigabe verlangen, bevor kritische Folgeänderungen verbindlich werden.
10. Nach Freigabe betroffene GBU, Betriebsanweisungen, Unterweisungen, Prüfpläne, Rechtskataster, Dokumente, Audits oder Management Reviews als Folgeaufgabe aktualisieren.

## Sicherheits- und Datenschutzgrenzen

- Keine Secrets oder personenbezogenen Rohdaten in Quellen-Snapshots.
- Keine externen KI-Provider ohne Mandantenfreigabe für vertrauliche Inhalte.
- Änderungsanalyse und Quellenstatus werden auditierbar gehalten.
- Keine automatische irreversible Rechts-/Compliance-Entscheidung.
- Keine ungeprüfte automatische Löschung, Veröffentlichung oder Kundenbenachrichtigung.
