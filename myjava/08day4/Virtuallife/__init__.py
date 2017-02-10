from Person import Person
from Story import Story
from Car import Car
from School import School
from Choice import Choice
import time

if __name__ == '__main__':
    story = Story()
    story.introduce()
    story.wait(3)
    story.Begining()
    story.wait(3)
    choice = Choice()
    choice.choice1()
    story.wait(3)
    story.Transmission()
    story.wait(3)
    story.interview()
    story.wait(3)
    story.Fightingyears()
    story.wait(3)
    story.endline()
    choice.choice2()