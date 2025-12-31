# LunaOS Versioning Scheme

> **TL;DR**: `2025.12.100` — Year.Month.Build. One number to increment. Zero entropy.

## The Scheme

```
┌─────────────────────────────────────────────────────────────┐
│  OFFICIAL (public):        2025.12                          │
├─────────────────────────────────────────────────────────────┤
│  VERSION (all):            2025.12.100                      │
│  └── YYYY.MM.BBB - bump BBB (100→101→102) per release       │
├─────────────────────────────────────────────────────────────┤
│  BUILD DNA:                2025-12-27T14:32:15.123456789Z   │
│  └── Unique per compile, nanosecond precision               │
└─────────────────────────────────────────────────────────────┘
```

### Components

| Component | Format | Example | Purpose |
|-----------|--------|---------|---------|
| **Official** | `YYYY.MM` | `2025.12` | Public-facing, marketing, docs |
| **Version** | `YYYY.MM.BBB` | `2025.12.100` | VERSION file, compatible |
| **Build DNA** | ISO-8601 ns | `2025-12-27T14:32:15.123456789Z` | Unique build identification |

### Release Workflow

```bash
# First release of December 2025
2025.12.100

# Second release same month
2025.12.101

# January 2026 arrives
2026.01.100
```

> **Why start at 100?** Leading zeros are rejected by many tools (`2025.12.000` invalid).
> Starting at 100 preserves the 3-digit aesthetic while staying compatible.
> We "lose" 100 slots per month — but 900 releases/month is still plenty.

---

## Entropy Analysis: Why This Scheme?

### Information-Theoretic Entropy (bits of decision per release)

| Scheme | Decisions | Bits/Release | Sync Overhead | Total Entropy |
|--------|-----------|--------------|---------------|---------------|
| **SemVer (x.y.z)** | major/minor/patch? | ~1.58 bits | mental model | ██████████░░░░░░ **62%** |
| **CalVer YYYY.MM.DD** | none (date-locked) | 0 bits | calendar sync | ████████░░░░░░░░ **50%** |
| **Dual (DD + BBB)** | which scheme? + maintain 2 | ~2.0 bits | dual tracking | █████████████░░░ **85%** |
| **Unified YYYY.MM.BBB** | just increment BBB | 0 bits | none | ███░░░░░░░░░░░░░ **18%** |

### Final Score

```
SemVer:        ██████████████████░░░░░░░░░░░░  62%  (judgment overhead)
CalVer DD:     ███████████████░░░░░░░░░░░░░░░  50%  (calendar-locked)
Dual Scheme:   █████████████████████████░░░░░  85%  (complexity explosion)
Unified BBB:   █████░░░░░░░░░░░░░░░░░░░░░░░░░  18%  ← OPTIMAL
```

**Winner: Unified YYYY.MM.BBB** — mechanical increment, zero semantic judgment, one scheme everywhere, automatic freshness via build DNA.

---

## Implementation

### VERSION File

The `VERSION` file contains the current version:
```
2025.12.100
```

### Information Channels

```
User sees:     "Null 2025.12"               (clean, fresh)
Build uses:    "2025.12.100"                (compatible)
Debug shows:   "2025-12-27T14:32:15.123456789Z"  (exact build moment)
```

---

## FAQ

**Q: Build numbers go 100→999. What if I run out?**

A: The number simply grows: `2025.12.1000`, `2025.12.1001`, etc.

**Q: Why not just use git commit hashes?**

A: Commit hashes are excellent for *identification* but terrible for *comparison*. You can't look at `a3f7b2c` and `e9d1f4a` and know which is newer. `2025.12.142` > `2025.12.141` — instant, obvious, human-readable.

**Q: Why reset to 100 each month instead of continuing from the previous month?**

A: The month boundary reset serves as a natural "fresh start" signal. It also keeps numbers small and memorable. Nobody wants to debug `2025.12.47293`.

---

## Philosophy

> **Minimum entropy**: The best versioning scheme is the one that requires zero thought.
>
> Every decision point is a potential bug. Every judgment call is cognitive load.
> The unified BBB scheme reduces versioning to a mechanical increment —
> leaving brain cycles for actual engineering.

---

*Document created: 2025.12 | LunaOS Sovereign Release*
