using Microsoft.EntityFrameworkCore;
using proyecto_final_webconfig.Data;
using proyecto_final_webconfig.Models.Entities;

namespace proyecto_final_webconfig.Repository
{
    public class DevicesBlacklistRepository : IDevicesBlacklistRepository
    {
        private readonly EspressoContext espressoContext;

        public DevicesBlacklistRepository(EspressoContext espressoContext)
        {
            this.espressoContext = espressoContext;
        }

        public async Task<IEnumerable<DeviceBlacklist>> GetAllDevices()
        {
            return await espressoContext.DeviceBlacklists.ToListAsync();
        }

        public async Task<DeviceBlacklist> GetDeviceByID(int id)
        {
            return await espressoContext.DeviceBlacklists.Where(x => x.Id == id).FirstAsync();
        }

        public async Task<int> AddDeviceToBlacklist(DeviceBlacklist device)
        {
            _ = await espressoContext.DeviceBlacklists.AddAsync(device);
            return await espressoContext.SaveChangesAsync();
        }

        public async Task<int> RemoveDeviceToBlacklist(int id)
        {
            DeviceBlacklist device = await GetDeviceByID(id);
            if (device == null)
            {
                return 0;
            }
            _ = espressoContext.DeviceBlacklists.Remove(device);
            return await espressoContext.SaveChangesAsync();
        }

    }
}
