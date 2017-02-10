from Mybank.AccountCheck import AccountCheck
from Mybank.CreditCardService import CreditCardService


if __name__ == '__main__':

    account_number = input('Please input your account number:')
    account = AccountCheck(account_number)
    account_verify = account.AccountVerify()
    if(account_verify):
        credit_card = account.LockVerify()
        if credit_card:
            account_password = account.PasswordCheck()
            service_id = input('please input you service id:')
            s = CreditCardService(account_number)
            s.serviceSelection(service_id)
    

