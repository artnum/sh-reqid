<?PHP
require('../src/ShReqId.php');

$rid = new artnum\ShReqId('local');
for ($i = 0; $i < 50000; $i++) {
    if($rid->set(hash('sha3-256', rand(1, 100)))) {
        echo 'ADD ' . $i . PHP_EOL;
    }
}
?>