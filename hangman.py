import random
from english_words import get_english_words_set


import re
HANGMAN_PICS = ['''
  3.   +---+
  4.       |
  5.       |
  6.       |
  7.      ===''', '''
  8.   +---+
  9.   O   |
 10.       |
 11.       |
 12.      ===''', '''
 13.   +---+
 14.   O   |
 15.   |   |
 16.       |
 17.      ===''', '''
 18.   +---+
 19.   O   |
 20.  /|   |
 21.       |
 22.      ===''', '''
 23.   +---+
 24.   O   |asd
 25.  /|\  |
 26.       |
 27.      ===''', '''
 28.   +---+
 29.   O   |
 30.  /|\  |
 31.  /    |
 32.      ===''', '''
 33.   +---+
 34.   O   |
 35.  /|\  |
 36.  / \  |
 37.      ===''']

web2lowerset = list(get_english_words_set(['web2'], lower=True))
word = web2lowerset[random.randint(0, len(web2lowerset))]
num = len(word)
answer = "_"*num
chances = 10
wrongs = 6
i=0
while wrongs>=1:
    print(HANGMAN_PICS[wrongs])
    print(answer)
    c = input("%d try :"%(i+1))
    i+=1
    indexs = [m.start() for m in re.finditer(c, word)]
    if indexs == list():
        wrongs-=1
        continue
    for k in indexs:
      list_ans = list(answer)
      list_ans[k] = list(word)[k]
      answer= "".join(list_ans)
    if answer == word:
        print("you win")
        break

print(HANGMAN_PICS[0])
print("you lose")

    

