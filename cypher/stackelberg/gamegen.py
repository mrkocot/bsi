import sys
import json
import random
from wonderwords import RandomWord


rw = RandomWord()


def randomDb(limit = 1.0):
    return round(random.random() * limit, 2)


def randomActionName():
    verb = rw.word(include_parts_of_speech=["verbs"]).capitalize()
    noun = rw.word(include_parts_of_speech=["nouns"])
    adj = rw.word(include_parts_of_speech=["adjectives"])
    return f'{verb} the {adj} {noun}'


def randomResourceName():
    noun1 = rw.word(include_parts_of_speech=["nouns"])
    adj = rw.word(include_parts_of_speech=["adjectives"])
    text = f'The {adj} {noun1}'
    if random.random() < .2:
        noun2 = rw.word(include_parts_of_speech=["nouns"])
        return f'{text} with a {noun2}'
    else:
        return text


def main():
    res = [f'res{i+1}' for i in range(int(sys.argv[1]))]
    dfc = [f'def{i+1}' for i in range(int(sys.argv[2]))]
    atk = [f'atk{i+1}' for i in range(int(sys.argv[3]))]
    path = sys.argv[4]

    game = {
        'resources': {},
        'defences': {},
        'attacks': {},
    }

    for a in atk:
        chance = {}
        for d in dfc:
            chance[d] = randomDb()
        game['attacks'][a] = {'name': randomActionName(), 'chance': chance}

    for d in dfc:
        game['defences'][d] = randomActionName()

    for r in res:
        ac = {}
        for a in atk:
            ac[a] = randomDb(100)
        dc = {}
        for d in dfc:
            dc[d] = randomDb(100)
        game['resources'][r] = {
            'name': randomResourceName(),
            'value': randomDb(300) + 90,
            'attackGain': randomDb(1000),
            'defenseCost': dc,
            'attackCost': ac,
        }

    with open(path, 'w') as json_file:
        json.dump(game, json_file, indent=2)


if len(sys.argv) < 5:
    print('4 arguments required - RESOURCES DEFENCES ATTACKS PATH')
else:
    main()
