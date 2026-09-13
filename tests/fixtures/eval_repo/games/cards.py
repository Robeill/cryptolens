import random

SUITS = ("clubs", "diamonds", "hearts", "spades")
RANKS = tuple(range(2, 15))


def new_deck():
    return [(rank, suit) for suit in SUITS for rank in RANKS]


def shuffle_deck(deck):
    random.shuffle(deck)
    return deck


def deal(deck, players):
    hands = [[] for _ in range(players)]
    for index, card in enumerate(deck):
        hands[index % players].append(card)
    return hands


def pick_starting_player(players):
    return random.choice(players)


def roll_dice(sides=6):
    return random.randint(1, sides)
