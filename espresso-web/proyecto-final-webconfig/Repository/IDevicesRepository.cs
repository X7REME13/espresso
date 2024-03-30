using proyecto_final_webconfig.Models.Entities;

namespace proyecto_final_webconfig.Repository
{
    public interface IDevicesRepository
    {
        Task<IEnumerable<Device>> GetAllBanDevices();
        Task<IEnumerable<Device>> GetAllDevices();
        Task<IEnumerable<Device>> GetAllUpDevices(DateTime startTimeFilter);
        Task<Device> GetDeviceByID(int id);
        Task<int> UpdateDevice(Device device);
    }
}