# Class to manage parking costs based on hours, days, months, or years
class Parking_Hours:
# Constructor method to initialize the object with name, car registration number, and parking rate
    def __init__(self, name, car_registration_number, parking_rate=14):
        self.name = name
        self.car_registration_number = car_registration_number
        self.parking_rate = parking_rate

# Method to calculate the cost for parking based on the number of hours
    def hours_parking(self, parking_hours):
        if parking_hours <= 0:
            print("Invalid number of hours")
            return None

        # Cost for parking for up to 1 hour without discount
        if parking_hours == 1:
            cost = 14
            
    # Discount of R4 for parking between 1 and 3 hours
        elif parking_hours > 1 and parking_hours <= 3:
            cost = (parking_hours * self.parking_rate) - 4

    # Discount of R6 for parking between 3 and 6 hours
        elif parking_hours > 3 and parking_hours <= 6:
            cost = (parking_hours * self.parking_rate) - 6

    # Discount of R11 for parking more than 7 hours
        elif parking_hours > 6:
            cost = (parking_hours * self.parking_rate) - 11
        
        return cost
    
     # Method to calculate the cost for parking based on the number of days
     # Calculate cost for daily parking with a fixed discount

    def daily_parking(self, number_of_days):
        if number_of_days <= 0:
            print("Invalid number of days")
            return None

        if number_of_days > 0:
            daily_hour = 24
            discount = 180
            daily_price = (daily_hour * self.parking_rate) - discount
            cost = daily_price * number_of_days
        

        return cost

    # Method to calculate the cost for parking based on the number of months 
    def monthly_parking(self, number_of_months):
        if number_of_months <= 0 or number_of_months >= 12:
            print("Invalid number of months")
            return None
        
        daily_price = 156
        number_of_days_in_month = 31
    # Calculate cost from 1 up to 4 months with a discount of R1500
        if number_of_months <= 4 and number_of_months > 0:
            discount = 1500
            monthly_price = (daily_price * number_of_days_in_month) - discount
            cost = number_of_months * monthly_price

    # Calculate cost for more than 4 months and less than a year with a discount of R2500
        elif number_of_months < 12 and number_of_months > 4:
            discount = 2500
            monthly_price = (daily_price * number_of_days_in_month) - discount
            cost = number_of_months * monthly_price
        else:
            print("Invalid number of months")


        return cost
    
    # Method to calculate the cost for parking based on the number of years
    def yearly_parking(self, number_of_years):
    
        if number_of_years <= 0:
            print("Invalid number of years")
            return None
        
    # Calculate cost for up to 5 years with a discount of R5000   
        if number_of_years <= 4 and number_of_years > 0:
            monthly_price = 3336
            discount = 5000
            yearly_price = (monthly_price * 12 * number_of_years) - discount

    # Calculate cost for more than 5 years with a discount of R8000
        else:
            number_of_years > 4
            monthly_price = 2336
            discount = 8000
            yearly_price = (monthly_price * 12 * number_of_years) - discount
        
        return yearly_price


# Main function to run the parking management system
def main():
    print("Durban Online Parking")
    name = input("Enter your Name: ")
    car_registration_number = input("Enter your Car registration number: ")
    
    while True:
        try:
            user = int(input("Press 1 for hourly parking, Press 2 for daily parking, Press 3 for monthly parking, Press 4 for yearly parking, Press 0 to Exit: "))
            
            if user == 0:
                break

        # Create an instance of the ParkingHours class    
            park = Parking_Hours(name, car_registration_number)
            cost = None
        
        # Depending on the user's choice, call the appropriate method    
            if user == 1:
                parking_hours = float(input("Enter hours you wish to park: "))
                cost = park.hours_parking(parking_hours)
            
            elif user == 2:
                number_of_days = float(input("Enter number of days you wish to park: "))
                cost = park.daily_parking(number_of_days)
            
            elif user == 3:
                number_of_months = float(input("Enter number of months you wish to park: "))
                cost = park.monthly_parking(number_of_months)
            
            elif user == 4:
                number_of_years = float(input("Enter number of years you wish to park: "))
                cost = park.yearly_parking(number_of_years)
            
            if cost is not None:
                print(f"Hi {park.name.upper()} with Car Registration Number {park.car_registration_number.upper()}, Your parking cost price is R{cost}")
            else:
                print("Invalid input. Please try again.")

        except ValueError:
          print("Invalid input. Please enter a number.")


# Run the main function if this script is executed
if __name__ == "__main__":
    main()



