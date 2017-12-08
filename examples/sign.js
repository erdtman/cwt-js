const CWT = require('../');

// Create
const signKey = {
  'd': Buffer.from('6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19', 'hex')
};
const alg = 'ES256';
const kid = 'AsymmetricECDSA256';
const claims = {
  'iss': 'coap://as.example.com',
  'sub': 'erikw',
  'aud': 'coap://light.example.com',
  'exp': 1444064944,
  'nbf': 1443944944,
  'iat': 1443944944,
  'cti': '0b71'
};

const cwt = CWT.create(claims);
cwt.sign(signKey, alg, kid).then(output => {
  console.log(output.toString('hex'));
});

// Verify
const verifyKey = {
  'x': Buffer.from('143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f', 'hex'),
  'y': Buffer.from('60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9', 'hex')
};

const token = Buffer.from('d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131680c429a01f85951ecee743a52b9b63632c57209120e1c9e30', 'hex');

CWT.read(token, verifyKey).then(claims => {
  console.log(claims);
}).catch(error => {
  console.log(error);
});
