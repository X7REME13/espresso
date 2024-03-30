using Microsoft.EntityFrameworkCore;
using proyecto_final_webconfig.Data;
using proyecto_final_webconfig.Models.Entities;

namespace proyecto_final_webconfig.Repository
{
    public class DevicesRepository : IDevicesRepository
    {
        private readonly EspressoContext espressoContext;

        public DevicesRepository(EspressoContext espressoContext)
        {
            this.espressoContext = espressoContext;
        }

        public async Task<IEnumerable<Device>> GetAllDevices()
        {
            return await espressoContext.Devices.ToListAsync();
        }
        public async Task<IEnumerable<Device>> GetAllUpDevices(DateTime startTimeFilter)
        {
            return await espressoContext.Devices.Where(d => d.LastUpDetected >= startTimeFilter).ToListAsync();
        }

        public async Task<IEnumerable<Device>> GetAllBanDevices()
        {
            return await espressoContext.Devices.Where(d => d.IsBanned).ToListAsync();
        }

        public async Task<Device> GetDeviceByID(int id)
        {
            return await espressoContext.Devices.Where(x => x.Id == id).FirstAsync();
        }

        //update device
        public async Task<int> UpdateDevice(Device device)
        {
            espressoContext.Entry(device).State = EntityState.Modified;
            return await espressoContext.SaveChangesAsync();
        }


        ////remove device
        //public async Task<int> RemoveDevice(int id)
        //{
        //    Device device = await GetDeviceByID(id);
        //    if (device == null)
        //    {
        //        return 0;
        //    }
        //    _ = espressoContext.Devices.Remove(device);
        //    return await espressoContext.SaveChangesAsync();
        //}

    }
}
