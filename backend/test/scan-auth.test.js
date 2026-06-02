const scanRepository = require('../src/modules/scans/scan.repository');
const { pool } = require('../src/db/pool');

jest.mock('../src/db/pool', () => ({ pool: { query: jest.fn() } }));

describe('Scan auth and isolation', () => {
  beforeEach(() => {
    pool.query.mockReset();
  });

  test('getScanById returns null for non-owner non-admin', async () => {
    // Simulate DB returning no scans for the query
    pool.query.mockResolvedValueOnce({ rowCount: 0, rows: [] });

    const result = await scanRepository.getScanById('scan-id', { userId: 'attacker', isAdmin: false });
    expect(result).toBeNull();
    expect(pool.query).toHaveBeenCalled();
  });

  test('getScanById returns scan with vulnerabilities for owner', async () => {
    const scanRow = { id: 'scan-1', project_name: 'proj', user_id: 'owner', status: 'completed' };
    const vulnerabilities = [{ id: 'v1', scan_id: 'scan-1', title: 'x', severity: 'low' }];

    pool.query
      .mockResolvedValueOnce({ rowCount: 1, rows: [scanRow] }) // get scan
      .mockResolvedValueOnce({ rowCount: 1, rows: vulnerabilities }); // get vulnerabilities

    const result = await scanRepository.getScanById('scan-1', { userId: 'owner', isAdmin: false });
    expect(result).not.toBeNull();
    expect(result.vulnerabilities).toEqual(vulnerabilities);
    expect(result.id).toBe('scan-1');
  });

  test('getScanById allows admin to fetch others scans', async () => {
    const scanRow = { id: 'scan-2', project_name: 'proj2', user_id: 'someone', status: 'running' };
    const vulnerabilities = [];

    pool.query
      .mockResolvedValueOnce({ rowCount: 1, rows: [scanRow] })
      .mockResolvedValueOnce({ rowCount: 0, rows: vulnerabilities });

    const result = await scanRepository.getScanById('scan-2', { userId: 'admin-user', isAdmin: true });
    expect(result).not.toBeNull();
    expect(result.id).toBe('scan-2');
  });

  test('listScans passes user isolation parameters to DB', async () => {
    const fakeRows = [{ id: 's1' }];
    pool.query.mockResolvedValueOnce({ rows: fakeRows });

    const scans = await scanRepository.listScans({ userId: 'u1', isAdmin: false });
    expect(scans).toEqual(fakeRows);
    expect(pool.query).toHaveBeenCalledTimes(1);
    const callArgs = pool.query.mock.calls[0];
    // second argument should be [isAdmin, userId]
    expect(callArgs[1]).toEqual([false, 'u1']);
  });
});
