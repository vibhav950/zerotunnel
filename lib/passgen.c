#include "common/defines.h"
#include "random/systemrand.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define N_WORDS_PER_LIST 256

static const char *PGP_WORDLIST_EVEN[N_WORDS_PER_LIST] = {
    "aardvark",  "absurd",    "accrue",    "acme",      "adrift",
    "adult",     "afflict",   "ahead",     "aimless",   "Algol",
    "allow",     "alone",     "ammo",      "ancient",   "apple",
    "artist",    "assume",    "Athens",    "atlas",     "Aztec",
    "baboon",    "backfield", "backward",  "banjo",     "beaming",
    "bedlamp",   "beehive",   "beeswax",   "befriend",  "Belfast",
    "berserk",   "billiard",  "bison",     "blackjack", "blockade",
    "blowtorch", "bluebird",  "bombast",   "bookshelf", "brackish",
    "breadline", "breakup",   "brickyard", "briefcase", "Burbank",
    "button",    "buzzard",   "cement",    "chairlift", "chatter",
    "checkup",   "chisel",    "choking",   "chopper",   "Christmas",
    "clamshell", "classic",   "classroom", "cleanup",   "clockwork",
    "cobra",     "commence",  "concert",   "cowbell",   "crackdown",
    "cranky",    "crowfoot",  "crucial",   "crumpled",  "crusade",
    "cubic",     "dashboard", "deadbolt",  "deckhand",  "dogsled",
    "dragnet",   "drainage",  "dreadful",  "drifter",   "dropper",
    "drumbeat",  "drunken",   "Dupont",    "dwelling",  "eating",
    "edict",     "egghead",   "eightball", "endorse",   "endow",
    "enlist",    "erase",     "escape",    "exceed",    "eyeglass",
    "eyetooth",  "facial",    "fallout",   "flagpole",  "flatfoot",
    "flytrap",   "fracture",  "framework", "freedom",   "frighten",
    "gazelle",   "Geiger",    "glitter",   "glucose",   "goggles",
    "goldfish",  "gremlin",   "guidance",  "hamlet",    "highchair",
    "hockey",    "indoors",   "indulge",   "inverse",   "involve",
    "island",    "jawbone",   "keyboard",  "kickoff",   "kiwi",
    "klaxon",    "locale",    "lockup",    "merit",     "minnow",
    "miser",     "Mohawk",    "mural",     "music",     "necklace",
    "Neptune",   "newborn",   "nightbird", "Oakland",   "obtuse",
    "offload",   "optic",     "orca",      "payday",    "peachy",
    "pheasant",  "physique",  "playhouse", "Pluto",     "preclude",
    "prefer",    "preshrunk", "printer",   "prowler",   "pupil",
    "puppy",     "python",    "quadrant",  "quiver",    "quota",
    "ragtime",   "ratchet",   "rebirth",   "reform",    "regain",
    "reindeer",  "rematch",   "repay",     "retouch",   "revenge",
    "reward",    "rhythm",    "ribcage",   "ringbolt",  "robust",
    "rocker",    "ruffled",   "sailboat",  "sawdust",   "scallion",
    "scenic",    "scorecard", "Scotland",  "seabird",   "select",
    "sentence",  "shadow",    "shamrock",  "showgirl",  "skullcap",
    "skydive",   "slingshot", "slowdown",  "snapline",  "snapshot",
    "snowcap",   "snowslide", "solo",      "southward", "soybean",
    "spaniel",   "spearhead", "spellbind", "spheroid",  "spigot",
    "spindle",   "spyglass",  "stagehand", "stagnate",  "stairway",
    "standard",  "stapler",   "steamship", "sterling",  "stockman",
    "stopwatch", "stormy",    "sugar",     "surmount",  "suspense",
    "sweatband", "swelter",   "tactics",   "talon",     "tapeworm",
    "tempest",   "tiger",     "tissue",    "tonic",     "topmost",
    "tracker",   "transit",   "trauma",    "treadmill", "Trojan",
    "trouble",   "tumor",     "tunnel",    "tycoon",    "uncut",
    "unearth",   "unwind",    "uproot",    "upset",     "upshot",
    "vapor",     "village",   "virus",     "Vulcan",    "waffle",
    "wallet",    "watchword", "wayside",   "willow",    "woodlark",
    "Zulu",
};

static const char *PGP_WORDLIST_ODD[N_WORDS_PER_LIST] = {
    "adroitness",  "adviser",     "aftermath",   "aggregate",  "alkali",
    "almighty",    "amulet",      "amusement",   "antenna",    "applicant",
    "Apollo",      "armistice",   "article",     "asteroid",   "Atlantic",
    "atmosphere",  "autopsy",     "Babylon",     "backwater",  "barbecue",
    "belowground", "bifocals",    "bodyguard",   "bookseller", "borderline",
    "bottomless",  "Bradbury",    "bravado",     "Brazilian",  "breakaway",
    "Burlington",  "businessman", "butterfat",   "Camelot",    "candidate",
    "cannonball",  "Capricorn",   "caravan",     "caretaker",  "celebrate",
    "cellulose",   "certify",     "chambermaid", "Cherokee",   "Chicago",
    "clergyman",   "coherence",   "combustion",  "commando",   "company",
    "component",   "concurrent",  "confidence",  "conformist", "congregate",
    "consensus",   "consulting",  "corporate",   "corrosion",  "councilman",
    "crossover",   "crucifix",    "cumbersome",  "customer",   "Dakota",
    "decadence",   "December",    "decimal",     "designing",  "detector",
    "detergent",   "determine",   "dictator",    "dinosaur",   "direction",
    "disable",     "disbelief",   "disruptive",  "distortion", "document",
    "embezzle",    "enchanting",  "enrollment",  "enterprise", "equation",
    "equipment",   "escapade",    "Eskimo",      "everyday",   "examine",
    "existence",   "exodus",      "fascinate",   "filament",   "finicky",
    "forever",     "fortitude",   "frequency",   "gadgetry",   "Galveston",
    "getaway",     "glossary",    "gossamer",    "graduate",   "gravity",
    "guitarist",   "hamburger",   "Hamilton",    "handiwork",  "hazardous",
    "headwaters",  "hemisphere",  "hesitate",    "hideaway",   "holiness",
    "hurricane",   "hydraulic",   "impartial",   "impetus",    "inception",
    "indigo",      "inertia",     "infancy",     "inferno",    "informant",
    "insincere",   "insurgent",   "integrate",   "intention",  "inventive",
    "Istanbul",    "Jamaica",     "Jupiter",     "leprosy",    "letterhead",
    "liberty",     "maritime",    "matchmaker",  "maverick",   "Medusa",
    "megaton",     "microscope",  "microwave",   "midsummer",  "millionaire",
    "miracle",     "misnomer",    "molasses",    "molecule",   "Montana",
    "monument",    "mosquito",    "narrative",   "nebula",     "newsletter",
    "Norwegian",   "October",     "Ohio",        "onlooker",   "opulent",
    "Orlando",     "outfielder",  "Pacific",     "pandemic",   "Pandora",
    "paperweight", "paragon",     "paragraph",   "paramount",  "passenger",
    "pedigree",    "Pegasus",     "penetrate",   "perceptive", "performance",
    "pharmacy",    "phonetic",    "photograph",  "pioneer",    "pocketful",
    "politeness",  "positive",    "potato",      "processor",  "provincial",
    "proximate",   "puberty",     "publisher",   "pyramid",    "quantity",
    "racketeer",   "rebellion",   "recipe",      "recover",    "repellent",
    "replica",     "reproduce",   "resistor",    "responsive", "retraction",
    "retrieval",   "retrospect",  "revenue",     "revival",    "revolver",
    "sandalwood",  "sardonic",    "Saturday",    "savagery",   "scavenger",
    "sensation",   "sociable",    "souvenir",    "specialist", "speculate",
    "stethoscope", "stupendous",  "supportive",  "surrender",  "suspicious",
    "sympathy",    "tambourine",  "telephone",   "therapist",  "tobacco",
    "tolerance",   "tomorrow",    "torpedo",     "tradition",  "travesty",
    "trombonist",  "truncated",   "typewriter",  "ultimate",   "undaunted",
    "underfoot",   "unicorn",     "unify",       "universe",   "unravel",
    "upcoming",    "vacancy",     "vagabond",    "vertigo",    "Virginia",
    "visitor",     "vocalist",    "voyager",     "warranty",   "Waterloo",
    "whimsical",   "Wichita",     "Wilmington",  "Wyoming",    "yesteryear",
    "Yucatan",
};

char *auth_passwd_generate_phonetic(int count, char sep, bool have_digits) {
  bool valid = false;
  char *pass;
  char buf[(9 * 10) + (11 * 10) + 21];
  uint32_t digit_idx;

  if (count < 3 || count > 20)
    return NULL;

  uint8_t randbytes[count];

  // The separator can only be a printable special character
  if (sep == 0) /* use the default separator */
    valid = true;
  else if (sep >= 33 /* ! */ && sep <= 47 /* / */)
    valid = true;
  else if (sep >= 58 /* : */ && sep <= 64 /* @ */)
    valid = true;
  else if (sep >= 91 /* [ */ && sep <= 98 /* ` */)
    valid = true;
  else if (sep >= 123 /* { */ && sep <= 126 /* ~ */)
    valid = true;

  if (!valid)
    return NULL;

  if (sep == 0)
    sep = '-';

  zt_systemrand_bytes(randbytes, count);

  digit_idx = have_digits ? zt_rand_ranged(count - 1) : count;

  int j = 0;
  for (int i = 0; i < count; i++) {
    const char *s;

    if (i % 2 == 0)
      s = PGP_WORDLIST_EVEN[randbytes[i]];
    else
      s = PGP_WORDLIST_ODD[randbytes[i]];

    strcpy(&buf[j], s);
    j += strlen(s);

    if (i == digit_idx)
      buf[j++] = 48 + zt_rand_ranged(9);
    if (i != count - 1)
      buf[j++] = sep;
  }
  buf[j++] = '\0';

  if (!(pass = zt_malloc(j))) {
    memzero(buf, j);
    return NULL;
  }
  zt_memcpy(pass, buf, j);
  memzero(buf, j);
  return pass;
}

/**
 * \p pass - buffer for nul-terminated password string
 * \p len - length of the password excluding null character
 */
int auth_passwd_generate(char *pass, int len) {
  if (len < 12 || len > 256)
    return -1;

  return zt_rand_charset(pass, len, NULL, 0);
}
