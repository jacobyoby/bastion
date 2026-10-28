# Witness UI design space

## Job

A person who is not a cryptographer, sitting at this computer, should feel that the computer was checked and that the result is a confirmation. The page should not feel like a log dump or a settings form.

The scan, the three outcomes (Confirmed, Needs attention, Incomplete), and the plain-language system-CA line stay fixed. Skipped public roots are counted, not weakness-scanned, and that line is not a green pass. This pass only changes how the same result is felt.

Five static pages of the same confirmed run were compared before any of this was built into `witness/web.py`: an instrument panel (the UI already shipped), an inspection certificate, a walkthrough’s last step, a traffic-light wall, and a technician’s clipboard. Same facts on each page: this machine, a time, no weak keys, no browser install, roots counted and not scanned, openssl noted, SSH empty.

## Directions

### 1. Instrument panel — rejected

What the user feels: a dashboard. A green status panel, then three result cards, then three more cards that are the controls, then a blue button.

What they do: tick Browsers, Installed apps, and SSH, press Confirm this machine, then read badges (clean, skipped, needs attention).

What fails the feel: the confirmation is one widget among others. Equal cards say “pick a feature.” A person cannot hand the page to someone without explaining the layout. This is the screen already shipped in the restyle that still looked like the previous form.

Rejected because it was already tried, and it still feels like software chrome rather than a check of this computer.

### 2. Inspection receipt — chosen

What the user feels: a sheet of paper you could hold up. Double border, the machine’s name, the time, a short ledger of what was witnessed, and a rubber stamp. Before the run the stamp says “Not yet issued.” After the run it says Confirmed, Needs attention, or Incomplete, and “Not signed,” so the sheet does not pretend to be a cryptographic receipt (signed receipts are out of scope).

What they do: read the blank certificate, leave the ruled lines for browsers, apps, and SSH ticked (or clear one), optionally add a TLS name, and press Confirm this machine. The issued sheet is the page. Witnessing again is a line under the certificate, not a second dashboard.

What fails the feel: three cards under the stamp (the instrument panel comes back); choice-cards instead of ruled lines; a filled green banner instead of ink; hiding “counted, not weakness-scanned” inside the stamp color; a green “Witnessed” on a section that only counted public roots; a stamp that looks like a signature; fine print that opens into a file table on a clean run. A throwaway of the blank sheet also failed when the line descriptions were squeezed into a one-word column. The lines that shipped keep the title and the description in the wide column. A section with a not-a-pass skip is marked “Not a pass,” in the same ink as the sheet, and the file table stays closed unless a key needs attention or a file could not be read.

Kept because the page itself is the confirmation.

### 3. Walkthrough — rejected

What the user feels: the end of a setup wizard. “Browsers, Apps, SSH, Stamp,” then “Step 4 of 4,” then the word Confirmed, then Start over.

What they do: answer one question at a time, then land on the stamp.

What fails the feel: the result is a place in a sequence, not an object. The last screen does not show what was witnessed, and it does not show that public roots were counted rather than passed. The check is one shot; splitting it into steps adds clicks and makes the product feel like onboarding.

Rejected because a non-cryptographer learns a flow instead of receiving a confirmation.

### 4. Traffic-light wall — rejected

What the user feels: a lamp. One large green circle, the word Confirmed at display size, one sentence, and a closed disclosure titled “What was checked.”

What they do: glance at the color. The machine name, the time, and the root-certificate line are behind that disclosure.

What fails the feel: the color becomes the product. It is the same family as the green status panel, only larger. A green wall can read as “all clear” while the honest line — counted, not weakness-scanned, not a pass — is hidden. There is nothing to hand someone that says which computer and which items.

Rejected because a light answers “is it ok?” and the job also needs “what was checked, on this machine, at this time.”

### 5. Technician clipboard — rejected

What the user feels: notes still on the pad. A clip, dashed rules, check marks, and a line that the sheet has not been torn off.

What they do: read a scratch list of browsers, apps, and SSH.

What fails the feel: it reads as work in progress. A list of checks is closer to a log than to a confirmation, even when every line is a pass. The physical metaphor is real, and it still does not close.

Rejected because the job is a finished confirmation, and a clipboard feels unfinished until something stamps it.

## Chosen direction

The inspection receipt.

It won because the page is the thing a person could hand someone else: this machine, this time, these items, and a stamp, with the “not a pass” line still on the sheet.
