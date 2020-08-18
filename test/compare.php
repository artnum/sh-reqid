<?PHP

/* on test machine :
 *   Running PHP Session 
 *   Running ShReqId 
 *   PHP Session : 0.0018164836530894
 *   ShReqId : 0.006073832988739
 *    
 * So it is actually slower ... might not be the right idea.
 */

require('../src/ShReqId.php');
$times = [
    [],
    []
];

ob_start();
echo 'Running PHP Session ' . PHP_EOL;
for ($i = 0; $i < 500; $i++) {
    $start = microtime(true);
    session_start();
    if (empty($_SESSION['history'])) {
        $_SESSION['history'] = [];
        $_SESSION['hSize'] = -1;
    }

    $h = hash('sha3-256', $i);
    $found = false;
    for($i = $_SESSION['hSize']; $i >= 0; $i--) {
        if ($_SESSION['history'][$i]['hash'] == $h) {
            $found = true;
            break;
        }
    }
    if (!$found) {
        $_SESSION['hSize']++;
        $_SESSION['history'][] = ['hash' => $h, 'time' => time()];
        if ($_SESSION['hSize'] > 45000) { // limit the number of request in history
            array_shift($_SESSION['history']);
            $_SESSION['hSize']--;
        }
    }
    session_write_close();
    $times[0][] = microtime(true) - $start;
}
ob_end_flush();

echo 'Running ShReqId ' . PHP_EOL;
for ($i = 0; $i < 500; $i++) {
    $start = microtime(true);
    $reqid = new artnum\ShReqId();
    $reqid->set(hash('sha3-256', $i));
    unset($reqid);
    $times[1][] = microtime(true) - $start;
}

for ($i = 0; $i < 2; $i++) {
    $total = 0;
    foreach($times[$i] as $t) {
        $total += $t;
    }
    $total /= count($times[$i]);
    $times[$i]['total'] = $total; 
}

echo 'PHP Session : ' . $times[0]['total'] . PHP_EOL;
echo 'ShReqId : ' . $times[1]['total'] . PHP_EOL;
?>