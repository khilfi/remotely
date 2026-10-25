//! SS-04, FD-07: passphrases Remotely makes up for a new vault password or export file: [`PASSPHRASE_WORDS`]
//! words drawn uniformly from [`WORDS`] with the operating system's CSPRNG (the one the vault's keys come
//! from), joined by `-`, such as `maple-orbit-tulip-canyon-velvet-ember`. Six words from 1327 give about
//! 62 bits, far beyond guessing with Argon2id in front of them, and they are easy to type and to write down.

use super::crypto;
use super::SecretString;
use crate::error::{CoreError, Result};

/// Words in a generated passphrase.
pub const PASSPHRASE_WORDS: usize = 6;

/// Longest word in [`WORDS`].
const MAX_WORD_LEN: usize = 8;

/// SS-04, FD-07: a new random passphrase. The UI shows it once so it can be written down; nothing keeps
/// it until the user submits it as the vault password or an export passphrase.
pub fn generate_passphrase() -> Result<SecretString> {
    let mut text = String::with_capacity(PASSPHRASE_WORDS * (MAX_WORD_LEN + 1));
    for i in 0..PASSPHRASE_WORDS {
        if i > 0 {
            text.push('-');
        }
        text.push_str(WORDS[random_below(WORDS.len())?]);
    }
    Ok(SecretString::new(text))
}

/// A uniform random number below `n`: 32 random bits, drawn again when they fall in the last partial
/// block of `n`, which would favour the first words.
fn random_below(n: usize) -> Result<usize> {
    let n = u64::try_from(n)
        .ok()
        .filter(|&n| n > 0 && n <= u64::from(u32::MAX))
        .ok_or_else(|| CoreError::Vault("no words to choose from".into()))?;
    let span = 1u64 << 32;
    let limit = span - span % n;
    loop {
        let mut bytes = [0u8; 4];
        crypto::random(&mut bytes)?;
        let value = u64::from(u32::from_le_bytes(bytes));
        if value < limit {
            return usize::try_from(value % n).map_err(|_| CoreError::Vault("no words to choose from".into()));
        }
    }
}

/// Short, common English words that are easy to spell, none of them in the strength check's list of
/// common passwords. Written for Remotely.
const WORDS: &[&str] = &[
    "abbey", "able", "absorb", "acorn", "acrobat", "adapt", "admiral", "admire", "advise", "agile", "airship", "alder",
    "alert", "align", "alley", "almanac", "almond", "aloe", "amber", "ample", "amuse", "anchor", "anchovy", "ancient",
    "ankle", "answer", "anthem", "anvil", "apricot", "apron", "arcade", "archer", "archery", "arctic", "arrive",
    "arrow", "artist", "aspen", "assemble", "atlas", "atom", "attic", "author", "avenue", "avocado", "axis", "axle",
    "azalea", "azure", "bacon", "badge", "badger", "bagel", "bake", "baker", "bakery", "balance", "balcony", "ballad",
    "ballet", "ballot", "bamboo", "banjo", "banner", "barber", "bargain", "barge", "barley", "barn", "barrel",
    "basement", "basil", "basket", "bathtub", "bazaar", "beach", "beacon", "beam", "bean", "beaver", "bedroom",
    "beige", "bell", "belt", "bench", "beret", "berry", "bicycle", "binary", "birch", "biscuit", "bishop", "bison",
    "blanket", "blimp", "blizzard", "blossom", "bobcat", "bold", "bolt", "bonnet", "boot", "borrow", "bottle",
    "boulder", "bounce", "bowl", "bowling", "boxing", "bracket", "bramble", "brave", "bread", "breathe", "breeze",
    "breezy", "brick", "bridge", "brief", "bright", "brisk", "broad", "bronze", "brook", "broom", "brownie", "bucket",
    "buckle", "buffalo", "buggy", "build", "bulletin", "bumpy", "bundle", "burrito", "busy", "butler", "butter",
    "button", "byte", "cabbage", "cabin", "cable", "cactus", "calm", "camel", "camera", "canary", "candid", "candle",
    "canoe", "canvas", "canyon", "captain", "carbon", "careful", "caribou", "carnival", "carpet", "carriage", "carrot",
    "carry", "cart", "carve", "cashew", "castle", "casual", "catch", "cavern", "cedar", "ceiling", "celery", "cell",
    "cellar", "cello", "century", "ceramic", "cereal", "chain", "chalk", "chapel", "chapter", "chariot", "chase",
    "checkers", "cheer", "cheerful", "cheetah", "chef", "cherry", "chess", "chicken", "chili", "chilly", "chimney",
    "chisel", "chop", "chord", "chorus", "chrome", "circuit", "circus", "citadel", "civic", "clap", "clarinet", "clay",
    "clean", "clerk", "clever", "cliff", "climb", "clock", "closet", "cloud", "cloudy", "clover", "coach", "coast",
    "coastal", "cobalt", "cobra", "cocoa", "coconut", "coffee", "collar", "collect", "comb", "comedy", "comet",
    "comic", "compass", "condor", "cook", "copper", "coral", "cork", "cosmic", "cosmos", "cottage", "cotton", "cougar",
    "count", "cove", "cowboy", "coyote", "cozy", "crab", "cracker", "cradle", "crane", "crater", "crawl", "crayon",
    "cream", "creek", "crepe", "cricket", "crimson", "crisp", "crow", "crown", "cruiser", "crystal", "cuff", "cumin",
    "cupboard", "curious", "curling", "curly", "current", "curry", "curtain", "cushion", "custard", "cyan", "cycling",
    "cyclone", "cymbal", "cypress", "daisy", "dance", "dancer", "daring", "darts", "dash", "dawn", "dazzling",
    "decade", "deep", "deer", "deliver", "delta", "denim", "dense", "desert", "design", "desk", "dial", "diary",
    "dinghy", "dingo", "distant", "dive", "dizzy", "dock", "doctor", "dolphin", "domino", "donkey", "doorway", "dove",
    "draft", "drama", "drawer", "drift", "drill", "drink", "drive", "drizzle", "drum", "drummer", "duck", "dumpling",
    "dune", "dusk", "eager", "eagle", "early", "earnest", "easel", "easy", "ebony", "echo", "eclipse", "editor",
    "egret", "elbow", "electron", "elegant", "element", "embark", "embassy", "ember", "emerald", "encore", "energy",
    "engine", "enjoy", "envelope", "enzyme", "epic", "escape", "estuary", "even", "evening", "exact", "explore",
    "fable", "fabric", "factory", "fair", "fairy", "faithful", "falcon", "famous", "fancy", "farm", "farmer", "fast",
    "faucet", "fearless", "fedora", "felt", "fence", "fencing", "fennel", "fern", "ferret", "ferry", "festival",
    "fetch", "fiber", "fiddle", "fierce", "fiesta", "finch", "finger", "fjord", "flag", "flame", "flamingo", "flask",
    "float", "florist", "flour", "fluffy", "flute", "fold", "folder", "follow", "forest", "forge", "fork", "formal",
    "fossil", "fountain", "fragile", "frame", "frank", "fresh", "friendly", "frisbee", "frost", "frosty", "fudge",
    "funnel", "fusion", "fuzzy", "gadget", "galaxy", "gale", "gallery", "gamma", "garage", "garden", "gardener",
    "garnet", "gate", "gather", "gazelle", "gear", "gecko", "gene", "gentle", "gerbil", "geyser", "giant", "gibbon",
    "gifted", "giggle", "giraffe", "glacier", "glad", "glade", "glass", "gleaming", "glen", "glide", "glider",
    "glossy", "glove", "gnome", "goat", "goblet", "goblin", "golf", "gondola", "goose", "gopher", "gorge", "gorilla",
    "grab", "graceful", "grand", "granite", "granola", "grape", "grateful", "gravity", "gravy", "great", "green",
    "greet", "griffin", "grind", "grouse", "grove", "grow", "guard", "guava", "guide", "guitar", "gulch", "gull",
    "gusty", "hail", "hallway", "hammer", "hammock", "hamster", "handle", "handy", "hangar", "happy", "harbor",
    "hardy", "hare", "harmony", "harp", "hasty", "hatchet", "hawk", "haze", "hazel", "hearty", "heather", "heavy",
    "hedgehog", "helium", "helmet", "helpful", "hemlock", "herald", "hermit", "heron", "hidden", "hike", "hiking",
    "hill", "hinge", "hippo", "hollow", "honest", "honey", "hood", "hook", "horizon", "hornet", "hose", "hostel",
    "hotel", "hour", "hover", "humble", "hummus", "hungry", "hunt", "hydrogen", "hyena", "ibex", "iceberg", "idle",
    "iguana", "impala", "indigo", "invent", "iron", "island", "isle", "isotope", "ivory", "jackal", "jacket", "jade",
    "jaguar", "jasmine", "jeep", "jelly", "jester", "jockey", "jogging", "jolly", "journal", "journey", "joyful",
    "judge", "judo", "juggle", "jump", "jungle", "juniper", "kale", "karate", "kayak", "kebab", "keen", "kelp",
    "kestrel", "kettle", "khaki", "kimono", "kind", "kiosk", "kitchen", "kite", "kiwi", "knee", "kneel", "knight",
    "knit", "knock", "koala", "kraken", "ladder", "ladle", "lagoon", "lake", "lamp", "lantern", "large", "laser",
    "latch", "laugh", "launch", "laurel", "lava", "lavender", "lawyer", "lazy", "lean", "learn", "leather", "ledge",
    "ledger", "legend", "lemon", "lemur", "lens", "lentil", "leopard", "letter", "lettuce", "lever", "library",
    "lichen", "lift", "lilac", "lily", "lime", "linden", "linen", "lion", "listen", "lithium", "lively", "lizard",
    "llama", "lobster", "local", "locket", "locust", "lodge", "lofty", "lorry", "lotus", "loud", "lounge", "loyal",
    "lucid", "lunar", "lynx", "lyric", "macaw", "magenta", "magnet", "magnolia", "magpie", "mailbox", "mallard",
    "mallet", "manatee", "mango", "mantle", "manual", "maple", "marble", "marigold", "market", "marmot", "maroon",
    "marsh", "marten", "mask", "mason", "mattress", "mayor", "meadow", "medal", "meerkat", "mellow", "melody", "melon",
    "memo", "mend", "mermaid", "merry", "mesa", "meteor", "midnight", "mighty", "mild", "mill", "miner", "mingle",
    "mink", "mint", "minute", "mirror", "mist", "misty", "mitten", "modern", "modest", "mole", "molecule", "moment",
    "monk", "monorail", "monsoon", "moon", "moose", "moraine", "morning", "mortar", "mosaic", "moss", "moth",
    "mountain", "mouse", "muddy", "muffin", "mule", "mural", "museum", "myrtle", "myth", "nail", "napkin", "narrow",
    "narwhal", "navigate", "navy", "nebula", "needle", "neon", "nettle", "neutron", "newt", "nibble", "nickel",
    "nimble", "noble", "noisy", "nomad", "noodle", "noon", "notebook", "novel", "nucleus", "nurse", "nutmeg", "nylon",
    "nymph", "oasis", "oatmeal", "observe", "ocean", "ocelot", "ochre", "octopus", "offer", "ogre", "olive", "onion",
    "onyx", "opal", "opera", "optic", "orbit", "orchard", "orchid", "orderly", "oregano", "organ", "oriole", "osprey",
    "ostrich", "otter", "oven", "oxygen", "oyster", "paddle", "pail", "paint", "painter", "palace", "palm", "pamphlet",
    "pancake", "panda", "panther", "pantry", "papaya", "paper", "paprika", "parade", "park", "parrot", "particle",
    "pasta", "patient", "patio", "pause", "pavilion", "pawn", "peaceful", "peach", "peanut", "pear", "pearl", "pebble",
    "pecan", "pedal", "pelican", "pencil", "penguin", "peony", "perfect", "pewter", "pheasant", "phoenix", "photon",
    "piano", "piccolo", "pickle", "picnic", "pier", "pigeon", "pillow", "pilot", "pine", "pipe", "piranha", "pirate",
    "pitcher", "pixel", "pixie", "pizza", "plain", "planet", "plank", "plant", "plasma", "plateau", "platinum",
    "platypus", "play", "playful", "plaza", "pliers", "plow", "plum", "plumber", "pocket", "poem", "poet", "poetry",
    "polish", "polite", "polo", "polymer", "poncho", "pond", "ponder", "pony", "popcorn", "poplar", "poppy", "porch",
    "possum", "poster", "potato", "potter", "pour", "prairie", "praise", "pretzel", "primrose", "print", "prism",
    "prize", "proton", "proud", "pudding", "puffin", "pull", "pulley", "pulse", "puma", "pumpkin", "push", "puzzle",
    "python", "quail", "quantum", "quarry", "quartz", "quest", "quick", "quiet", "quill", "quilt", "quince", "quiver",
    "rabbit", "raccoon", "race", "radar", "radio", "radish", "radius", "raft", "rain", "rainbow", "raisin", "rake",
    "ranch", "rapid", "rapids", "rare", "raven", "ravine", "ravioli", "reach", "read", "ready", "receipt", "recipe",
    "redwood", "reed", "reef", "regal", "relax", "repair", "report", "rescue", "rhythm", "ribbon", "rice", "rich",
    "rickshaw", "riddle", "ride", "ridge", "rigid", "river", "roam", "robe", "robin", "robust", "rock", "rocket",
    "roll", "rook", "rope", "rose", "rosy", "round", "rover", "rowan", "rowing", "royal", "ruby", "rudder", "rugby",
    "rugged", "ruler", "rush", "rust", "rustic", "saddle", "safari", "saffron", "saga", "sage", "sail", "sailing",
    "sailor", "salad", "salmon", "salsa", "sand", "sandal", "sandy", "sapphire", "sardine", "satchel", "saucer",
    "savanna", "scan", "scarf", "scarlet", "scholar", "school", "scissors", "scooter", "scout", "screw", "scroll",
    "sculpt", "seal", "search", "season", "sedan", "sensor", "sepia", "sequoia", "settle", "shake", "share", "shark",
    "shawl", "shed", "sheep", "shelf", "sheriff", "shield", "shine", "shiny", "shore", "shoulder", "shout", "shovel",
    "shower", "shrimp", "shuttle", "sickle", "signal", "silent", "silk", "simple", "sing", "singer", "sink", "skating",
    "sketch", "skiing", "skip", "skunk", "slate", "sled", "sleek", "sleepy", "sleet", "sleeve", "sleigh", "slide",
    "slim", "slipper", "sloop", "slope", "sloth", "smile", "smooth", "snail", "sneeze", "snow", "snowy", "sock",
    "socket", "sofa", "soft", "solar", "solid", "solve", "sonar", "sonata", "sonnet", "sorbet", "sorrel", "sort",
    "soup", "sparkly", "sparrow", "spatula", "spectrum", "speedy", "sphere", "sphinx", "spicy", "spider", "spin",
    "spinach", "spindle", "splash", "spoon", "sprint", "sprite", "sprout", "spruce", "squall", "squash", "squid",
    "stable", "stack", "stadium", "stamp", "stapler", "star", "static", "station", "statue", "steady", "steel",
    "steppe", "stew", "stir", "stone", "stool", "stork", "storm", "story", "stove", "stream", "stretch", "string",
    "stroll", "studio", "sturdy", "subway", "suede", "sugar", "sumac", "summit", "sunny", "sunrise", "sunset",
    "surfing", "sushi", "swamp", "swan", "sweater", "swift", "swim", "swing", "switch", "table", "tablet", "tackle",
    "taco", "tailor", "tale", "talk", "tall", "tame", "tapir", "taxi", "teach", "teacher", "teal", "teapot", "temple",
    "tempo", "tender", "tennis", "tent", "termite", "terrace", "thaw", "theater", "theory", "thimble", "thistle",
    "throw", "thrush", "thumb", "thunder", "thyme", "ticket", "tickle", "tide", "tidy", "tile", "timber", "tiny",
    "titan", "toad", "toast", "toaster", "tofu", "token", "tomato", "topaz", "torch", "toss", "toucan", "tough",
    "towel", "tower", "trace", "tractor", "trail", "tram", "tranquil", "travel", "trek", "troll", "trolley",
    "trombone", "trophy", "trout", "trowel", "truck", "true", "truffle", "trumpet", "trunk", "trusty", "tuba",
    "tugboat", "tulip", "tumble", "tuna", "tundra", "tunic", "tunnel", "turkey", "turnip", "turtle", "tutor", "tweed",
    "twilight", "twirl", "typhoon", "ukulele", "umber", "umbrella", "unfold", "unicorn", "unlock", "upbeat", "urban",
    "valiant", "valley", "vanilla", "vase", "vast", "vector", "velvet", "venture", "verse", "vertex", "vest", "viking",
    "village", "vineyard", "violet", "violin", "viper", "visit", "vivid", "volcano", "voltage", "voyage", "vulture",
    "wade", "waffle", "wagon", "wait", "waiter", "wallet", "walnut", "walrus", "waltz", "wand", "wander", "warden",
    "wardrobe", "warm", "wary", "wash", "wasp", "watch", "watt", "wave", "wavy", "wealthy", "weasel", "weave",
    "weaver", "whale", "wharf", "wheat", "wheel", "whisper", "whistle", "wide", "wiggle", "wild", "willow", "wind",
    "window", "windy", "wink", "wise", "wisteria", "witty", "wizard", "wobble", "wolf", "wombat", "wonder", "wool",
    "woolly", "workshop", "wren", "wrench", "wrist", "write", "xenon", "yacht", "yarn", "yarrow", "yawn", "yell",
    "yoga", "yogurt", "young", "yoyo", "zany", "zebra", "zeppelin", "zesty", "zinc", "zipper", "zoom",
];

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::vault::strength::{password_strength, COMMON};

    #[test]
    fn passphrases_are_six_listed_words_and_always_strong() {
        let listed: HashSet<&str> = WORDS.iter().copied().collect();
        let mut seen = HashSet::new();
        for _ in 0..200 {
            let phrase = generate_passphrase().unwrap();
            let words: Vec<&str> = phrase.expose().split('-').collect();
            assert_eq!(words.len(), PASSPHRASE_WORDS);
            assert!(words.iter().all(|w| listed.contains(w)), "{words:?}");
            let strength = password_strength(phrase.expose());
            assert!(strength.acceptable && strength.score == 4, "{words:?}: {strength:?}");
            seen.insert(phrase.expose().to_owned());
        }
        assert_eq!(seen.len(), 200, "random passphrases repeat");
    }

    #[test]
    fn the_word_list_is_clean_and_large_enough() {
        assert!(WORDS.len() >= 1024, "{} words: under 60 bits for six", WORDS.len());
        let mut seen = HashSet::new();
        for word in WORDS {
            assert!((4..=MAX_WORD_LEN).contains(&word.len()), "{word}");
            assert!(word.chars().all(|c| c.is_ascii_lowercase()), "{word}");
            assert!(seen.insert(*word), "{word} twice");
            assert!(!COMMON.contains(word), "{word} is a common password");
        }
    }

    #[test]
    fn every_word_can_be_drawn() {
        let mut counts = [0usize; 4];
        for _ in 0..4000 {
            counts[random_below(4).unwrap()] += 1;
        }
        assert!(counts.iter().all(|&c| c > 800), "{counts:?}");
        assert!(random_below(0).is_err());
        assert_eq!(random_below(1).unwrap(), 0);
    }
}
