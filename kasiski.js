/**
 *  Kasiski Examination Library
 *  Written by Alex Truong
 *  License: MIT
 */

// Because Kasiski Examination sounds cooler than Kasiski's Method

/**
 *  factorGap(n, factorTable)
 *  Records frequency and computes factors of occurring substring lengths.
 *  See recurrenceSearch for the structure of the factorTable.
 */
function factorGap(n, factorTable){
    if (factorTable[n]) return factorTable[n].frequency++;

    // Initialize the factorization object
    factorTable[n] = {};
    factorTable[n].frequency = 1;
    factorTable[n].factorList = [];

    // Determine factors
    for (var i = 2; i <= Math.sqrt(n); i++){
        if (n % i === 0){
            factorTable[n].factorList[i] = true;
        }
    }
}

/** 
 *  recurrenceSearch(ciphertext)
 *  Searches for and records all repeated, non-overlapping substrings for Kasiski Examination.
 *  The results of this search are packaged in an object with the following fields:
 *      substringTable: An associative list of (key, value) pairs (substring, {indexOfAppearance, gapToNextAppearance}) where
 *                      substring:              The repeating substring
 *                      indexOfAppearance:      The index in which the substring appears in the ciphertext
 *                      gapToNextAppearance:    The index difference between this occurrence and the next one in the ciphertext
 *      factorTable:    An array of factor objects where the jth element is {frequency, factorList} where
 *                      frequency:              The number of times that substring gap was exactly j
 *                      factorList:             The list of non-trivial factors (i.e. excluding 1 and j)
 */
function recurrenceSearch(ciphertext){
    // Tables to be computed and returned
    var substringTable = {}; // Recurring strings
    var factorTable = []; // Recurring gap factors
    
    // We're using the naive method here, because Ukkonen's algorithm and suffix trees are too cumbersome to use here
    // The optimization may be appreciated for much longer ciphertexts, but in such a case, you likely wouldn't be using this

    // Iterate over all k-length repeated, non-overlapping substrings (k > 1)
    // Since they must not overlap, it can only be as long as half the string
    for (var k = 2; k < Math.floor(ciphertext.length/2); k++) {
        // Because of this, we need not check if there isn't enough room for it to appear twice (n-2k)
        for (var startIndex = 0; startIndex < ciphertext.length - 2*k; startIndex++) {
            var candidate = ciphertext.substring(startIndex, startIndex + k);
            
            // We begin searching past the end of the substring
            var searchIndex = startIndex + k;
            var nextIndex = -1;
            var gap;
            do {
                nextIndex = ciphertext.indexOf(candidate, searchIndex);
                // We record every occurrence for display purposes
                if (nextIndex > -1){
                    // Initialize the candidate object
                    if (!substringTable[candidate])
                        substringTable[candidate] = [];

                    gap = nextIndex - startIndex;
                    substringTable[candidate].push({"indexOfAppearance": startIndex, "gapToNextAppearance": gap});
                    
                    // Count and determine factors
                    factorGap(gap, factorTable);

                    // Update index
                    searchIndex = nextIndex + k;
                }
            } while(nextIndex > -1);
        }
    }

    return [substringTable, factorTable];
}

/** 
 *  kasiskiExamination(ciphertext)
 *  Examines the results of the recurring string search to determine the most likely key lengths.
 *  The results of this search are packaged in an object with the following fields:
 *      substringTable: See recurrenceSearch
 *      factorTable:    See recurrenceSearch
 *      candidateFreqs: An array of factors and their frequencies, ordered numerically
 *      frequencyRanks: An array of factors and their frequencies, ranked by frequency
 *      firstKeyLength: The most likely key length, obtained from the first element of frequencyRanks
 */
function kasiskiExamination(ciphertext){
    // Unpackaging results of the function call (because this is not Python)
    var results = recurrenceSearch(ciphertext);
    var substringTable = results[0];
    var factorTable = results[1];

    // candidateFreqs stores the pristine factor objects
    var candidateFreqs = [];
    // frequencyRanks stores references to the same objects, but will be sorted afterwards
    var frequencyRanks = [];

    var factorCount = 0;

    for (var gap in factorTable){
        var frequency = factorTable[gap].frequency;

        for (var factor in factorTable[gap].factorList){
            if (!candidateFreqs[factor]){
                // Creating a new object, and pointing to it from the second array
                candidateFreqs[factor] = {"factor" : factor, "frequency" : frequency};
                frequencyRanks[factor] = candidateFreqs[factor];
                factorCount++;
            }
            else{
                candidateFreqs[factor].frequency += frequency;
            }
        }
    }

    // This comparison function ranks the entries (i.e. largest frequencies come first)
    frequencyRanks.sort(function compare(x, y){
        return y.frequency - x.frequency;
    });
    
    // Our suggestion should be the first key length larger than 3, based on security assumptions
    var firstKeyLengthIndex = 0;
    while (frequencyRanks[firstKeyLengthIndex].factor < 4){
        firstKeyLengthIndex++;
    }
    
    // Examination results
    return {
        "substringTable" : substringTable,
        "factorTable" : factorTable,
        "candidateFreqs" : candidateFreqs,
        "frequencyRanks" : frequencyRanks,
        "firstKeyLength" : frequencyRanks[firstKeyLengthIndex].factor
    };
}