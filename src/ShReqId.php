<?PHP
/* (c) 2020 Etienne Bagnoud <etienne@artnum.ch> */
namespace artnum;

use Exception;

use function PHPSTORM_META\map;

class ShReqId {
    const attributes = [
        'REQUEST_URI',
        'REQUEST_METHOD',
        'SERVER_PROTOCOL',
    ];
    /* slot is 32 bytes hash and 8 bytes timestamp */
    const slotSize = 40;
    const hashAlgo = 'sha3-256';
    const magicB0 = 0xEB; // nice to have initial fitting into hex value
    const lockTry = 12; // random number ... wyh not 12 tries
    protected $usleepTime = 120;
    protected $sessionTime = 900; // 15 minutes
    
    private $semId = null;
    private $shmopId = null;
    private $b0 = null;

    /* by default, history of last 45000 requests : 
     *  -> 50 req/sec = 15 minutes history
     *  -> about 2 megs of shared memory
     * 
     * sessionDuration is in minutes
     * 
     */
    function __construct ($domain = null, $slots = 45000, $sessionDuration = 15) {
        /* per-domain shared memory, can be run via cli anyway */
        if ($domain === null) {
            if (isset($_SERVER) && !empty($_SERVER['SERVER_NAME'])) {
                $domain = $_SERVER['SERVER_NAME'];
            } else {
                $domain = 'localhost';
            }
        }
        $tmpFile = sprintf('%s/shreqid-%s', sys_get_temp_dir(), $domain);
        if(!touch($tmpFile)) {
            throw new \Exception('Cannot get temporary file.');
        }
        
        /* semaphore for locking */
        $key = ftok($tmpFile, 'l');
        $semId = sem_get($key);
        if (!$semId) {
            throw new \Exception('Cannot get semaphore.');
        }
        $this->semId = $semId;

        $key = ftok($tmpFile, 's');
        $shmopId = @shmop_open($key, 'w', 0, 0);
        if (!$shmopId) {
            /* lock before creating new segment. avoid two process creating at same time */
            if (!$this->_locking()) {
                throw new \Exception('Cannot acquire lock for initialization.');
            }
            $shmopId = shmop_open($key, 'n', 0664, ($slots + 1) * self::slotSize);
            if (!$shmopId) {
                throw new \Exception('Cannot create shared memory segement.');
            }
            if(!$this->_initBlock0($shmopId)) {
                $this->_close_shmop();
                throw new \Exception('Cannot initialize block 0.');
            }

            if (!$this->_locking(true)) {
                $this->_close_shmop();
                throw new \Exception('Cannot release acquired semaphore.');
            }
        }
        $this->shmopId = $shmopId;      
        $this->slots = $slots;
        if ($sessionDuration > 0) {
            $this->sessionDuration = $sessionDuration * 60;
        }
    }

    function __destruct() {
        $this->_close_shmop();
    }

    private function _close_shmop() {
        if ($this->shmopId !== null) {
            shmop_close($this->shmopId);
        }
        $this->shmopId = null;
    }

    private function _locking($unlock = false) {
        $i = 0;
        do {
            $ret = false;
            if ($unlock) {
                $ret = sem_release($this->semId);
            } else {
                $ret = sem_acquire($this->semId, false);
            }
            if (!$ret) {
                usleep($this->usleepTime);
                $i++;
            } else {
                return true;
            }
        } while ($i < self::lockTry);
        return false;
    }

    function lock() {
        if(!$this->_locking()) {
            throw new \Exception('Cannot acquire lock.');
        }
        $this->_readb0();
    }

    private function _readb0() {
        $b0 = shmop_read($this->shmopId, 0, self::slotSize);
        $this->b0 = unpack('Cmagic/Ilast/Hwrap', $b0);
        if ($this->b0['magic'] !== self::magicB0) {
            throw new \Exception('Corrupted block 0.');
        }
    }

    function unlock() {
        if (!$this->_writeBlock0()) {
            throw new Exception('Cannot write back block 0.');
        }
        if(!$this->_locking(true)) {
            throw new \Exception('Cannot release lock.');
        }
        $this->b0 = null;
    }

    private function _initBlock0($shmopId) {
        return shmop_write($shmopId, pack('CIH', self::magicB0, 0, 0x00), 0);
    }

    private function _writeBlock0() {
        return shmop_write($this->shmopId, pack('CIH', self::magicB0, $this->b0['last'], $this->b0['wrap']), 0);
    }

    private function current() {
        if ($this->b0['magic'] === self::magicB0) {
            return $this->b0['last'];
        } else {
            throw new \Exception('Corrupted block 0');
        }
    }

    function firstEntry() {
        if ($this->b0['last'] === 0) { return false; }
        $this->current = $this->b0['last'];
        return unpack('H64hash/qtime', shmop_read($this->shmopId, $this->current * self::slotSize, self::slotSize), 0);
    }

    function nextEntry() {
        if ($this->current - 1 === 0) {
            if ($this->b0['wrap']) {
                $this->current = $this->slots;
            } else {
                return false;
            }
        } else {
            $this->current--;
        }
        if ($this->current === $this->b0['last']) { return false; }
        return unpack('H64hash/qtime', shmop_read($this->shmopId, $this->current * self::slotSize, self::slotSize), 0);
    }

    function set($value) {
        $pos = 0;

        $this->lock();
        $itsIn = false;
        for ($entry = $this->firstEntry(); $entry; $entry = $this->nextEntry()) {
            // entry too old
            if ($entry['time'] < (time() - $this->sessionDuration)) {
                break;
            }

            /* no point in using hash_equals here */
            if ($entry['hash'] === $value) {
                $itsIn = true;
                break;
            }
        }
        if (!$itsIn) {
            if ($this->b0['last'] + 1 > $this->slots) {
                $this->b0['last'] = 1;
                $this->b0['wrap'] = 0x01;
            } else {
                $this->b0['last']++;
            }
            shmop_write($this->shmopId, pack('H64q', $value, time()), self::slotSize * $this->b0['last']);
        }
        $this->unlock();


        return !$itsIn;
    }

    function reqid ($server) {
        $hCtx = hash_init(self::hashAlgo);
        /* request id is used as the only value if it's available */
        if (!empty($server['HTTP_X_REQUEST_ID'])) {
            hash_update($hCtx, $server['HTTP_X_REQUEST_ID']);
        } else {
            foreach (self::attributes as $attr) {
                if (!empty($server[$attr])) {
                    hash_update($hCtx, $server[$attr]);
                }
            }
        }
        return hash_final($hCtx);
    }
}

?>