const { CVSS40 } = require('./cvss40');
const fs = require('fs');
const path = require('path');

const testDataPaths = fs.readdirSync('./data').map(fileName => ({
  path: path.join('./data', fileName),
  name: fileName,
}));

describe('CVSS 4.0', () => {
  const testData = testDataPaths.reduce((data, file) => {
    const fileData = fs.readFileSync(file.path, 'utf8');
    const lineEntries = fileData.split('\n');
    const scoredVectors = lineEntries.map(vectorScore => {
      const vectorScorePair = vectorScore.trim().split(' - ');
      return (vectorScorePair.length !== 2) ? null : { vector: vectorScorePair[0], score: parseFloat(vectorScorePair[1]) };
    }).filter(Boolean);
    data[file.name] = scoredVectors;
    return data;
  }, {});

  Object.entries(testData).forEach(([fileName, vectorScores]) => {
    it(`should calculate scores in ${fileName} correctly`, () => {
      vectorScores.forEach(({ vector, score }) => {
        expect(new CVSS40(vector).score).toBe(score);
      });
    });
  });
});
