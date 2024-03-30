using proyecto_final_webconfig.Models.Entities;

namespace proyecto_final_webconfig.Services
{
    public interface IDevicesService
    {
        Task<int> BanDevice(int id);
        Task<IEnumerable<Device>> GetAllBanDevices();
        Task<IEnumerable<Device>> GetAllUpDevices();
        Task<Device> GetDeviceByID(int id);
        Task<int> UnbanDevice(int id);
    }
}