//
//  RSATest.swift
//  CryptoSwift
//
//  Created by MinLison on 2017/8/14.
//  Copyright © 2017年 Marcin Krzyzanowski. All rights reserved.
//
import XCTest
import Foundation
@testable import CryptoSwift

final class RSATests: XCTestCase {
    func testRSA() {
       let DEFAULT_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAikpsOH+2mxy7tpNQvODuB19tzi/h112nZGHUz8Xem80AIrO6IT/m5CDncZ+bE2XkDeIDrzEvXJktQMHgANRsfRYcd2/GxBP61kKsnrWjS+cljJoN7TmMHDlzdslSeIcOa6diP72ADp8zD5DkTwYVWcJ6Ly5xP9tWIookL2DgBwicWZutWKNTkJeoigpCMqyFrKK+Bh6bHSofHDBhA6Fpac597x1sfnwwAgPOfljA7YjUegcu4uAaNHNH9m/THU04N1StLSAOrfGy/71F8jYKep6LpVW3Slq64krZaoqu2YLH0eE0vKmphuZyTHxqyk/lgzGDHolZqXXQ3h3Hntp1QQIDAQAB";
        
        let DEFAULT_PRIVATE_KEY = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCKSmw4f7abHLu2k1C84O4HX23OL+HXXadkYdTPxd6bzQAis7ohP+bkIOdxn5sTZeQN4gOvMS9cmS1AweAA1Gx9Fhx3b8bEE/rWQqyetaNL5yWMmg3tOYwcOXN2yVJ4hw5rp2I/vYAOnzMPkORPBhVZwnovLnE/21YiiiQvYOAHCJxZm61Yo1OQl6iKCkIyrIWsor4GHpsdKh8cMGEDoWlpzn3vHWx+fDACA85+WMDtiNR6By7i4Bo0c0f2b9MdTTg3VK0tIA6t8bL/vUXyNgp6noulVbdKWrriStlqiq7ZgsfR4TS8qamG5nJMfGrKT+WDMYMeiVmpddDeHcee2nVBAgMBAAECggEAIGt6G3S1Vn/R8edvUhhZNRlGIMRQ6bBnAb19qof0vAm/MmN4Cztz4Z9lItoL/OwyHp8Rxgx90fOHDFtnLEqgdGKuocFuk6ErePeAiGSEt9KkluW2xhpromJFk193GhJvawV+nvrJ/qOL0OZi37PJZZWWF2GH4zSEaOyBtym622rsb+lv0P2yJO6f4+OyCUOeeHc8DoegydZv1GJJj2r54E2EmzyGYUAedkTuMe65OCKNCYpLYcWYneM3sq6qHEqDip8kwO2ysO6soSMkFhcveJUWJSDqiHxLt+czRppokjRKL86x1dVwJQETVPY5chcw3kYy3q4DAXccqv/MrMS/AQKBgQDVdub0mWDLARtqz0P60UCai1FQARBE/UR153BoqNnI6KrdCOmaNl+ezxeu5Gp0tU1oJJR+swEMEn/amb8szubRKTj0ECpb/4gyYyfhyGL/Mr5cYHbjqm3gZwNZU5XrJ4ZSaA7MLOr2rcii4zni4VDbdgkWUIVACu/X3DOR1q+8uQKBgQCl2M+E6452HxoNkSAoGyVGThP4a8SRJsZf6VWQwM+ac42E5NnAUsztEYqKhpZVs+/j1aAxwIz4WM5YAKy0QNwbp+PhonvvnyBtwMcobNGvYA9kwGMhlL9lLOrwKexQUKnwtoVEj+PsMUXtb6Hdrrvw1WNS7iBU0AIr5HK2mwWIyQKBgQDAooqNlZRZ3mflnaGVSRzp2mvIrQ0HlR8g33j7mdTfj8gRrCdTeVoVMIII3CyNocd3AfvX0qZRRKiIl1KElzqI6pBw/92aJCG+hujIwlNERYCwUIU5suVxKsVE6T9TdNmsqCcibi6j6fQzuqbUbczQH9bXgladksEapacMJxd0UQKBgAIomULcogUNkJQ+oFGFUO3iVEY2eN9+xrQ24EM7DziualghdmgXa81mHgyBhfFlnyiy/hvHqs4MsdrZX2YVNggyHjgwmjZbNtvW14DCMdR7hpfEHUYxnnAdro0jroy5EA0vAvsKeGf5mDRn8I5nGNEgpeNNcCRKdMzHc2rHB8JpAoGBAJQxoaEABch1tjokg1cDETjXx25S3/WtsShymtUdS4k32s20XXYJ/ns1sZY1iFK/Fk9n5u50mwVPd5ZdkXdApWPRdaPhdiSn6ZCgMZp81KpT+O5i7DVstGn3YrFUpF+piKn60WKYM8AOgJ2f/TRKkTLw6MQpUym22iNCxkXNWu3x";
        
        
        let testString = "!@#$%^&*():?><@#&%&*?"
        
        let encryptStr = testString.rsa_encrypt(public_key: DEFAULT_PUBLIC_KEY)!;
        
        print("encryptStr str \n \n\(encryptStr)");
        let encryptStrTest = "Y7LZrbE3wbNWrJLBgcd63IscP4tH096GijsZC2J7gMy41M2Paasl6CSkQd7KXr2gihxDXI83JrH1u5rJXULtuP6lNlYydJrq3ySvwV8aKNbXlRt/CZiGkKjYpJmHCtivv/tVUBZUnHRrq50o7lv2xylQnnFYXwXu+hJ/VxDukm2VqZFFf2arlr10/ExPG6rEMJqS4ZApWQX3PUhGeca4CXldmTJNaek0rwyO/rv++RKl8pYai0obkJaHHOOTN7CSHd4ltmMg7inJaf2YzM4IjTwlLGwVoZnZ59FomHkF+ZDzli577/VFLwOZOoP3sV5g/XBnUnhxevkStDxT40Gy+g==";
        let decryptStr = encryptStrTest.rsa_decrypt(private_key: DEFAULT_PRIVATE_KEY);
        print("decrypt str \n \n\(decryptStr)");
    }
        
}
