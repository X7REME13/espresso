using proyecto_final_webconfig.Models.Entities;

namespace proyecto_final_webconfig.Repository
{
    public interface IDevicesBlacklistRepository
    {
        Task<int> AddDeviceToBlacklist(DeviceBlacklist device);
        Task<IEnumerable<DeviceBlacklist>> GetAllDevices();
        Task<DeviceBlacklist> GetDeviceByID(int id);
        Task<int> RemoveDeviceToBlacklist(int id);
    }
}