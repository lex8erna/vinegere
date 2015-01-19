/**
 *  Vigenere Cipher Library
 *  Written by Alex Truong
 *  License: MIT
 */

/*  Frequencies obtained from Project Gutenberg:
 *  Source: http://www3.nd.edu/~busiforc/handouts/cryptography/Letter%20Frequencies.html#Results_from_Project_Gutenberg
 *  Note: The percentages have been converted to unit ratios (i.e. in range 0 to 1). Because stats.
 *  Note 2: Wow, this is a lot of words for something that just describes a division by 100.
 */
var letterFrequencies = {   "A": 0.08000395,
                            "B": 0.01535701,
                            "C": 0.02575785,
                            "D": 0.04317924,
                            "E": 0.12575645,
                            "F": 0.02350463,
                            "G": 0.01982677,
                            "H": 0.06236609,
                            "I": 0.06920007,
                            "J": 0.00145188,
                            "K": 0.00739906,
                            "L": 0.04057231,
                            "M": 0.02560994,
                            "N": 0.06903785,
                            "O": 0.07591270,
                            "P": 0.01795742,
                            "Q": 0.00117571,
                            "R": 0.05959034,
                            "S": 0.06340880,
                            "T": 0.09085226,
                            "U": 0.02841783,
                            "V": 0.00981717,
                            "W": 0.02224893,
                            "X": 0.00179556,
                            "Y": 0.01900888,
                            "Z": 0.00079130};

/** CLASS: Vigenere - Constructor
 *  Vigenere(cryptotext, key)
 *  A class for encrypting/decrypting/analysing Vigenere plaintexts/ciphertexts.
 */
var Vigenere = function(cryptotext, key){
    // Input key: Default to empty key (outputs original character with the modular operations below)
    this.key = (key || " ").toUpperCase();

    // Input text
    this.cryptotext = (cryptotext || " ").toUpperCase();

    // Output text
    this.plaintext = cryptotext;
    this.ciphertext = cryptotext;

    // Pointer to frequencies object
    this.letterFrequencies = letterFrequencies;
}

/** CLASS: Vigenere - Method
 *  Object.setText(text)
 *  Sets the working text.
 */
Vigenere.prototype.setText = function (text){
    this.cryptotext = text;
};

/** CLASS: Vigenere - Method
 *  Object.setKey(key)
 *  Sets the working key.
 */
Vigenere.prototype.setKey = function (key){
    this.key = (key || " ").toUpperCase();
};

/** CLASS: Vigenere - Method
 *  Object.reset()
 *  Resets the output texts.
 */
Vigenere.prototype.reset = function (){
    this.plaintext = this.cryptotext;
    this.ciphertext = this.cryptotext;
};

/** CLASS: Vigenere - Method
 *  Object.cyclicPlus()
 *  Computes addition modulo 26 for the zero-first order-mapped English alphabet.
 */
Vigenere.prototype.cyclicPlus = function cyclicPlus(x, c){
    // Operate only on upper case letters
    if (x.match(/^[A-Z]$/) && c.match(/^[A-Z]$/)){
        return String.fromCharCode((x.charCodeAt(0) + c.charCodeAt(0) - 65*2) % 26 + 65);
    }
    // Otherwise, we leave it unchanged
    else{
        return x;
    }
};

/** CLASS: Vigenere - Method
 *  Object.cyclicMinus()
 *  Computes subtraction modulo 26 for the zero-first order-mapped English alphabet.
 */
Vigenere.prototype.cyclicMinus = function cyclicMinus(x, c){
    // Operate only on upper case letters
    if (x.match(/^[A-Z]$/) && c.match(/^[A-Z]$/)){
        // For minus, the two -65's cancel out; we need to add 26 to deal with negative wraparounds
        return String.fromCharCode((x.charCodeAt(0) - c.charCodeAt(0) + 26) % 26 + 65);
    }
    // Otherwise, we leave it unchanged
    else{
        return x;
    }
};

/** CLASS: Vigenere - Method
 *  Object.encrypt()
 *  Encrypts the working text using the stored key, or a new key, if available.
 */
Vigenere.prototype.encrypt = function(newKey){
    var key = newKey || this.key;
    var ciphertext = "";
    for (var i = 0; i < this.cryptotext.length; i++){
        ciphertext += this.cyclicPlus(this.cryptotext.charAt(i), key.charAt(i % key.length));
    }
    return this.ciphertext = ciphertext;
};

/** CLASS: Vigenere - Method
 *  Object.decrypt()
 *  Decrypts the working text using the stored key, or a new key, if available.
 */
Vigenere.prototype.decrypt = function(newKey){
    var key = newKey || this.key;
    var plaintext = "";
    for (var i = 0; i < this.cryptotext.length; i++){
        plaintext += this.cyclicMinus(this.cryptotext.charAt(i), key.charAt(i % key.length));
    }
    return this.plaintext = plaintext;
};

/** CLASS: Vigenere - Method
 *  Object.frequencies()
 *  Computes the column-wise frequencies of the provided text, and its chi-squared score relative to the English language.
 *  The results of this search are packaged in an array containing frequency objects, where each letter and its frequency is a key, value pair,
 *      in addition to the total count in the cosets (column-wise string partitions), and the computed chi-squared score.
 */
Vigenere.prototype.frequencies = function(columns, cryptotext){
    // We default to simple substitution cipher
    columns = columns || 1;
    cryptotext = cryptotext || this.cryptotext;

    // Initialize column frequency table
    var columnFrequencies = [];
    for (var i = 0; i < columns; i++){
        columnFrequencies[i] = {};
        columnFrequencies[i].total = 0;
        for (var letter in this.letterFrequencies){
            columnFrequencies[i][letter] = 0;
        }
    }
    
    // Count occurrences of letters
    for (var i = 0; i < cryptotext.length; i++){
        var column = i % columns;
        var letter = cryptotext.charAt(i);
        if (!letter.match(/^[A-Z]$/)) continue;
        
        columnFrequencies[column][letter]++;
        columnFrequencies[column].total++;

    }

    // Calculate chi-squared score for each column frequency using the formula as follows:
    // X^2 = Sum of all (f_i - F_i)^2/F_i, where:
    //      f_i : observed frequency of the ith letter
    //      F_i : expected frequency of the ith letter
    for (var i = 0; i < columns; i++){
        var column = i;
        var score = 0;
        for (var letter in this.letterFrequencies){
            columnFrequencies[column][letter] /= columnFrequencies[column].total;
            score += Math.pow(columnFrequencies[column][letter] - this.letterFrequencies[letter], 2)/this.letterFrequencies[letter];
        }
        columnFrequencies[column].score = score;
    }

    return columnFrequencies;
}

/** CLASS: Vigenere - Method
 *  Object.kasiskiExamination()
 *  If kasiski.js was included, we attach kasiskiExamination just for syntactic sugar.
 *  Refer to kasiski.js for documentation.
 */
// 
if (kasiskiExamination){
    Vigenere.prototype.kasiskiExamination = function (){
        return kasiskiExamination(this.cryptotext);
    }
}

/** CLASS: Vigenere - Method
 *  Object.smashKey()
 *  Computes the most likely candidate(s) for the key using chi-squared keyword recovery, and ranks the remaining letters.
 *  The results of this search are packaged in an object with the following fields:
 *      candidateTable: An associative list of (key, value) pairs (substring, {indexOfAppearance, gapToNextAppearance}) where
 *                      substring:              The repeating substring
 */
Vigenere.prototype.smashKey = function(length, options){
    // If no length is provided and kasiski.js is included, we default to the Kasiski Examination
    // Otherwise, we default to simple substitution cipher
    if (this.kasiskiExamination)
        length = length || this.kasiskiExamination().firstKeyLength || 1; // Sanity checking
    else
        length = length || 1;

    // We default to three choices (one suggested, two alternatives) per character in the key
    options = Math.min(options || 3, 26);

    // Initialize candidate key components table
    var candidateTable = [];
    for (var column = 0; column < length; column++){
        candidateTable[column] = [];
    }

    // Compute chi-squared scores for decryptions under each letter and insert for sorting
    for (var letter in this.letterFrequencies){
        var shiftedText = this.decrypt(letter);
        var frequencies = this.frequencies(length, shiftedText);
        for (var column = 0; column < length; column++){
            candidateTable[column].push({"letter": letter, "score" : frequencies[column].score});
        }
    }

    // Attempt to obtain the most likely candidate for the key, though this is not always the actual key
    var firstKey = "";
    // Sort scores on a column-by-column basis
    function compare(x, y){
        return x.score - y.score;
    };
    for (var column = 0; column < length; column++){
        // When comparing chi-squared scores, smaller is better
        candidateTable[column].sort(compare);
        firstKey += candidateTable[column][0].letter;
    }

    // Key smashing results
    return {
        "candidateTable" : candidateTable,
        "firstKey" : firstKey,
        "assemble" : function (combination){
            var newKey = "";
            for (var column = 0; column < this.candidateTable.length; column++){
                newKey += this.candidateTable[column][combination[column]].letter;
            }
            return newKey;
        }
    };
};