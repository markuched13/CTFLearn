### Lazy Game Challenge CTFLearn

### Difficulty = Easy

### Link = https://ctflearn.com/challenge/691/16330

This was a really fun one that required applying logic 

Given a netcat remote instance to connect to

```
nc thekidofarcrania.com 10001
```

On connecting to the remote server it shows some sort of game 

```
Welcome to the Game of Luck !. 

Rules of the Game :
(1) You will be Given 500$
(2) Place a Bet
(3) Guess the number what computer thinks of !
(4) computer's number changes every new time !.
(5) You have to guess a number between 1-10
(6) You have only 10 tries !.
(7) If you guess a number > 10, it still counts as a Try !
(8) Put your mind, Win the game !..
(9) If you guess within the number of tries, you win money !
(10) Good Luck !..

theKidOfArcrania:
  I bet you cannot get past $1000000!


Are you ready? Y/N : 
```

The rule is already given that we need to more than $1000000 

Lets play it then

```
Are you ready? Y/N : Y
Money you have : 500$
Place a Bet : 100

Loading : ⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛ 100%
The Game is On, Good Luck !..

Make a Guess : 2

Computer's number :  10
Your Guess :  2
Sorry Wrong Guess, Try Again !. -_- 

Computer's number :  8
Your Guess :  10
Sorry Wrong Guess, Try Again !. -_- 

Computer's number :  4
Your Guess :  1
Sorry Wrong Guess, Try Again !. -_- 

[[-----------------SNIP-------------]]

Computer's number :  3
Your Guess :  3

You made it !.
You won JACKPOT !..
You thought of what computer thought !.
Your balance has been updated !

Current balance : 700$
Want to play again? Y/N : N

Thank you for playing ! 
Made by John_123
Small mods by theKidOfArcrania
Give it a (+1) if you like !..
```

It's possible to at least get the value the computer chooses then we can continue to play it starting from round 1 and after round 10 and you don't get any correct value it exits

At first i attempted brute forcing the guesses but i failed in doing so :(

Then i noticed the way money is been added / removed

Here's the logic i presumed the server uses ( also i figured that its python i'll give my reason at the end of the post )

```
1. After printing out all the banner & rules it receives our input on if we want to play or not
2. If we choose to play it then gives us an initial amount ($500) where we can take the money to bet on the guessing game
3. It created a random randint value ranging from 1 to 10
4. The user guess is then compared with the random value
5. If the user guess is equal to the random value it adds the amount placed on the bet to the initial amount which is $500 
6. But if it isn't it subtracts the amount placed on the bet to the initial amount which is $500 
```

So here's how i think it should look like

```
import random

def guess_game():
    print("Welcome to the Guess the Number Game!\n")
    print("The rules are simple, you start with $500 and you can place your bet.")
    print("I will choose a random number from 1 to 10 and you have to guess it.")
    print("If you guess it right, you win the amount that you bet.")
    print("If you guess it wrong, you lose the amount that you bet.")
    print("Let's start the game!\n")
    
    money = 500
    play = input("Do you want to play? (Y/N) ")
    
    while play == 'Y' or play == 'y':
        print("You have $" + str(money) + " now.")
        bet = int(input("How much do you want to bet? "))
        
        while bet > money:
            print("You don't have enough money.")
            bet = int(input("How much do you want to bet? "))
        
        random_number = random.randint(1, 10)
        guess = int(input("Enter your guess (1-10): "))
        
        if guess == random_number:
            money += bet
            print("Congratulations! You won $" + str(bet))
        else:
            money -= bet
            print("Sorry, the number was " + str(random_number) + ". You lost $" + str(bet))
        
        play = input("Do you want to play again? (Y/N) ")
    
    print("Thanks for playing! You leave with $" + str(money))

guess_game()
```

Now the code looks secure but no here's the issue

This is how the basic function is if you lose

```
>>> amount = 500
>>> stake = 100
>>> loss = amount - stake
>>> loss
400
>>>
```

But no here's the issue

```
>>> amount = 500
>>> stake = -100
>>> loss = amount - stake
>>> loss
600
>>>
```

We see that if the staked bet is a negative value it adds it to the total amount lost 

Lets confirm it

```
Welcome to the Game of Luck !. 

Rules of the Game :
(1) You will be Given 500$
(2) Place a Bet
(3) Guess the number what computer thinks of !
(4) computer's number changes every new time !.
(5) You have to guess a number between 1-10
(6) You have only 10 tries !.
(7) If you guess a number > 10, it still counts as a Try !
(8) Put your mind, Win the game !..
(9) If you guess within the number of tries, you win money !
(10) Good Luck !..

theKidOfArcrania:
  I bet you cannot get past $1000000!


Are you ready? Y/N : 
```

The rule is already given that we need to more than $1000000 

Lets play it then

```
Are you ready? Y/N : Y
Money you have : 500$
Place a Bet : -100

Loading : ⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛ 100%
The Game is On, Good Luck !..

Make a Guess : 2

Computer's number :  10
Your Guess :  2
Sorry Wrong Guess, Try Again !. -_- 

Computer's number :  8
Your Guess :  10
Sorry Wrong Guess, Try Again !. -_- 

Computer's number :  4
Your Guess :  1
Sorry Wrong Guess, Try Again !. -_- 

[[-----------------SNIP-------------]]

Computer's number :  3
Your Guess :  3

Your balance has been updated !.
Current balance :  : 
600$
Want to play again? Y/N : Thank you for playing ! 
Made by John_123
Small mods by theKidOfArcrania
Give it a (+1) if you like !..
```

It worked sweet 😸 

So here's the math to get the exact value needed

```
>>> amount = 500
>>> target = 1100000
>>> win = amount - target
>>> win
-1099500
>>>
```

Since the tasked says `I bet you cannot get past $1000000!` thats why i use a value above `1000000`

I'll run it now using `-1099500` as the money to stake then the guess i'll give is going to be `0`

```
Are you ready? Y/N : Y
Money you have : 500$
Place a Bet : -1099500

Loading : ⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛⬛ 100%
The Game is On, Good Luck !..

Make a Guess : 0

Computer's number :  10
Your Guess :  0
Sorry Wrong Guess, Try Again !. -_- 

Computer's number :  8
Your Guess :  0
Sorry Wrong Guess, Try Again !. -_- 

Computer's number :  4
Your Guess :  0
Sorry Wrong Guess, Try Again !. -_- 

[[-----------------SNIP-------------]]

Computer's number :  3
Your Guess :  0

Sorry you lost some money !..
Your balance has been updated !.
Current balance :  : 
1100000$
What the... how did you get that money (even when I tried to stop you)!? I guess you beat me!

The flag is CTFlearn{i_wish_real_********************_like_this!}
```

I also did make a solve scipt you can check it out (same directory as this file is in) but its basically just doing the same thing i did manually

Now here's how i knew that this remote server file is a python file 

On giving it a string instead of an integer in the stake amount input it gives an error 

```
Money you have : 500$
Place a Bet : A
Traceback (most recent call last):
  File "/server.py", line 57, in <module>
    spent = int(input('Place a Bet : '))
ValueError: invalid literal for int() with base 10: 'A'
```

Thats how i knew 🤓 

And we're done 
