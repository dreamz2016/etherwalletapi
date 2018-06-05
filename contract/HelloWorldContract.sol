// You will also need a solidity linter for ATOM ! like linter-solidity
// FILE : HelloWorldContract.sol
// Notice the .sol (for solidity) extension.
pragma solidity ^0.4.0;
// will not compile with a compiler earlier than version 0.4.0
contract HelloWorldContract {
// notice the word contract 
 function sayHi() constant returns (string){
// As a typed language, this function specifies what it returns via the constant returns (string) bit.
    return 'Hello World';
  }
}